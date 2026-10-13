-- ============================================================
-- CRM Phase 0b — CRM tables + attribution plumbing (no UI)
-- ============================================================
--
-- ATTRIBUTION DESIGN (ChatGPT lane — product/data-model reasoning)
--
-- One canonical source enum, `crm_source`, is used on EVERY intake
-- surface (contacts, leads, vendor intake, bookings, profiles,
-- event tickets) so per-source revenue reporting in Phase 4 groups
-- by a single type instead of five differently-spelled text columns.
--
-- Enum values (§5 channels, exact):
--   facebook_group, tiktok, instagram, google, realtor_referral,
--   event, sms_keyword, walk_in, other
-- Deliberately NOT extended: the legacy onboarding options
-- `youtube` and `friend_family` (onboarding_answers.heard_about_us)
-- map to 'other' with the original value preserved verbatim in
-- `source_detail` (e.g. source_detail='youtube'). Extending the enum
-- for every legacy free-text value would fork the taxonomy Jeremy
-- approved in §5; the mapping table lives in the Phase 4 backfill
-- notes, not in the type.
--
-- NULL vs 'other' semantics (the skeptic's rule, R10):
--   NULL    = attribution was never captured (legacy rows, system-
--             created rows). Reports must EXCLUDE or separately label
--             these — never silently fold them into a channel.
--   'other' = attribution WAS captured and the source is genuinely
--             none of the 8 named channels (with source_detail saying
--             what it was). This is data, not a gap.
-- New intake code (Phase 1+) must always set source; the column stays
-- nullable only so legacy rows keep their honest NULL.
--
-- Carriage lead → job → commission (per-source revenue in Phase 4):
--   crm_leads.source/campaign_tag  → copied at conversion into
--   jobs.source/campaign_tag       → jobs aggregate into the 3%
--   referral ledger (commissions.computed_from_cents) in Phase 3.
--   The copy is done by conversion code (Phase 1/3), not by trigger:
--   a trigger would hide the business rule; explicit code keeps the
--   moment of conversion auditable. jobs.source stays nullable so
--   pre-CRM jobs keep NULL (never captured).
--
-- Dedupe / identity keys:
--   * crm_contacts: canonical identity is the normalized phone.
--     `phone_normalized` is GENERATED from crm_normalize_phone(),
--     which mirrors lib/dnc.ts normalizePhone exactly (strip
--     non-digits; 10-digit US numbers get +1; longer digit strings
--     are assumed to carry their country code; empty → NULL).
--     UNIQUE on phone_normalized; NULL phones (no phone) never
--     collide because Postgres treats NULLs as distinct. The DB —
--     not app code — is the final dedupe arbiter.
--   * crm_communications ingest idempotency (R8): UNIQUE on
--     (contact_id, channel, direction, occurred_at). Ingest code MUST
--     truncate occurred_at to second precision before insert —
--     millisecond skew between Voice/Sheets/relay clocks would
--     otherwise defeat the key. `source_ref` (outreach_request id /
--     sheet row / voice id) is recorded for audit but is NOT the key:
--     the same event can arrive from two stores with different refs.
--   * funnel_entries: UNIQUE(contact_id, funnel) — one live state
--     machine per contact per funnel; a repeated keyword re-enters
--     the same row (stage timestamps advance), it does not fork.
--   * event_tickets: UNIQUE on stripe_payment_intent_id (partial,
--     WHERE NOT NULL) — the Stripe webhook is the idempotency key.
--
-- Append-only audit (crm_communications): enforced by TRIGGER
-- (BEFORE UPDATE OR DELETE → RAISE EXCEPTION), which binds even the
-- service_role. RLS additionally grants no UPDATE/DELETE policies.
-- A touch log you can rewrite is not a touch log.
--
-- §4 SPEC GAPS found (not silently guessed — see report):
--   G1. `crm_leads` vs dead `public.leads`: resolved by RENAME —
--       public.leads becomes crm_leads (verified: zero code refs,
--       zero FKs to it). agent_id → owner_id, status → legacy_status
--       (renames, not drops — nothing is destroyed). New canonical
--       `stage` enum added; legacy_status stays until Phase 1
--       confirms the table's rows, then a cleanup migration drops it.
--   G2. scheduled_posts already HAS scheduled_for + author_id (§4
--       lists scheduled_for as "add" — redundant). Added: created_by
--       (= the staff user who drafted it; author_id stays the post
--       owner), needs_approval, approved_by/at. "Never instant for
--       sales-created" is a code rule for Phase 2, not schema.
--   G3. funnel_entries.attached_draft_id has no FK: drafts live in
--       the SOP markdown until Phase 2 surfaces them in lead cards.
--       Column is text + documented; FK comes with the drafts table.
--   G4. event_tickets.event is open text, not an enum: events are
--       unbounded (nov7_2026, qa_oct20_2026, …) — an enum would need
--       a migration per event. Convention documented in column comment.
--   G5. profiles backfill of attribution_source from
--       onboarding_answers.heard_about_us is NOT run here: mapping
--       free-text legacy values is a data decision for Jeremy's
--       review (Phase 4), not a silent migration rewrite.
-- ============================================================

-- ── canonical enums ───────────────────────────────────────────
DO $$ BEGIN
  CREATE TYPE public.crm_source AS ENUM (
    'facebook_group','tiktok','instagram','google','realtor_referral',
    'event','sms_keyword','walk_in','other'
  );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  CREATE TYPE public.crm_visibility AS ENUM ('team','owner_only');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  CREATE TYPE public.crm_lead_stage AS ENUM (
    'new','contacted','qualified','quoted','follow_up','won','lost'
  );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  CREATE TYPE public.crm_channel AS ENUM ('sms','call','email','messenger','note');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  CREATE TYPE public.crm_direction AS ENUM ('in','out');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  CREATE TYPE public.crm_funnel AS ENUM ('none','vendor','realtor');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  CREATE TYPE public.crm_funnel_stage AS ENUM (
    'keyword_received','draft_attached','approved','sent','replied','onboarded'
  );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- ── phone normalization (IMMUTABLE so a generated column can use it;
--    mirrors lib/dnc.ts normalizePhone exactly) ────────────────
CREATE OR REPLACE FUNCTION public.crm_normalize_phone(raw text)
RETURNS text LANGUAGE sql IMMUTABLE
SET search_path = public
AS $$
  SELECT CASE
    WHEN raw IS NULL OR regexp_replace(raw, '\D', '', 'g') = '' THEN NULL
    WHEN length(regexp_replace(raw, '\D', '', 'g')) = 10
      THEN '+' || '1' || regexp_replace(raw, '\D', '', 'g')
    ELSE '+' || regexp_replace(raw, '\D', '', 'g')
  END
$$;

-- ── revive dead public.leads as crm_leads (G1) ─────────────────
-- Renames are guarded for re-run safety (RENAME has no IF EXISTS).
-- Column renames propagate to the old RLS policies automatically
-- (Postgres rewrites dependent expressions); the policies themselves
-- are replaced in phase0c.
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables
             WHERE table_schema = 'public' AND table_name = 'leads') THEN
    ALTER TABLE public.leads RENAME TO crm_leads;
  END IF;
END $$;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = 'crm_leads'
               AND column_name = 'agent_id') THEN
    ALTER TABLE public.crm_leads RENAME COLUMN agent_id TO owner_id;
  END IF;
END $$;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = 'crm_leads'
               AND column_name = 'status') THEN
    ALTER TABLE public.crm_leads RENAME COLUMN status TO legacy_status;
  END IF;
END $$;

ALTER TABLE public.crm_leads
  ADD COLUMN IF NOT EXISTS stage public.crm_lead_stage NOT NULL DEFAULT 'new',
  ADD COLUMN IF NOT EXISTS stage_changed_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS lost_reason text,
  ADD COLUMN IF NOT EXISTS funnel public.crm_funnel NOT NULL DEFAULT 'none',
  ADD COLUMN IF NOT EXISTS assigned_at timestamptz,
  ADD COLUMN IF NOT EXISTS source public.crm_source,
  ADD COLUMN IF NOT EXISTS source_detail text,
  ADD COLUMN IF NOT EXISTS campaign_tag text,
  ADD COLUMN IF NOT EXISTS origin_post_id uuid REFERENCES public.feed_posts(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS utm_source text,
  ADD COLUMN IF NOT EXISTS utm_medium text,
  ADD COLUMN IF NOT EXISTS utm_campaign text,
  ADD COLUMN IF NOT EXISTS utm_content text;

-- ── crm_contacts ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.crm_contacts (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name             text,
  phone            text,
  -- Canonical identity: generated, unique. NULL phones never collide.
  phone_normalized text GENERATED ALWAYS AS (public.crm_normalize_phone(phone)) STORED UNIQUE,
  email            text,
  city             text,
  -- Attribution: every intake carries source (§5). NULL = never captured.
  source           public.crm_source,
  source_detail    text,  -- group name / post URL / referrer / legacy verbatim
  campaign_tag     text,
  origin_post_id   uuid REFERENCES public.feed_posts(id) ON DELETE SET NULL,
  utm_source       text,
  utm_medium       text,
  utm_campaign     text,
  utm_content      text,
  -- Visibility (R1): owner_only rows are invisible to the sales role —
  -- enforced in phase0c RLS. owner_id = the Jeremy-owned contact owner.
  owner_id         uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
  visibility       public.crm_visibility NOT NULL DEFAULT 'team',
  -- Inert Phase 0 scaffolding: no send path reads this column — every
  -- regulated send checks dnc_registry via lib/dnc.ts only. Wiring
  -- (sheet-marker import / UI toggle sync) comes in Phase 1.
  do_not_contact   boolean NOT NULL DEFAULT false,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  last_touch_at    timestamptz
);
CREATE INDEX IF NOT EXISTS crm_contacts_owner_idx      ON public.crm_contacts (owner_id);
CREATE INDEX IF NOT EXISTS crm_contacts_visibility_idx ON public.crm_contacts (visibility);
CREATE INDEX IF NOT EXISTS crm_contacts_source_idx     ON public.crm_contacts (source);
CREATE INDEX IF NOT EXISTS crm_contacts_campaign_idx   ON public.crm_contacts (campaign_tag);
CREATE INDEX IF NOT EXISTS crm_contacts_origin_post_idx ON public.crm_contacts (origin_post_id);
CREATE INDEX IF NOT EXISTS crm_contacts_last_touch_idx ON public.crm_contacts (last_touch_at DESC);

-- Attach the contact_id FK now that crm_contacts exists (Postgres must
-- resolve the referenced table at ALTER time). Re-run safe.
ALTER TABLE public.crm_leads
  ADD COLUMN IF NOT EXISTS contact_id uuid REFERENCES public.crm_contacts(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS crm_leads_owner_idx    ON public.crm_leads (owner_id);
CREATE INDEX IF NOT EXISTS crm_leads_stage_idx    ON public.crm_leads (stage);
CREATE INDEX IF NOT EXISTS crm_leads_contact_idx  ON public.crm_leads (contact_id);
CREATE INDEX IF NOT EXISTS crm_leads_source_idx   ON public.crm_leads (source);
CREATE INDEX IF NOT EXISTS crm_leads_campaign_idx ON public.crm_leads (campaign_tag);

-- ── crm_communications (APPEND-ONLY) ───────────────────────────
CREATE TABLE IF NOT EXISTS public.crm_communications (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  contact_id  uuid NOT NULL REFERENCES public.crm_contacts(id) ON DELETE RESTRICT,
  lead_id     uuid REFERENCES public.crm_leads(id) ON DELETE SET NULL,
  channel     public.crm_channel NOT NULL,
  direction   public.crm_direction NOT NULL,
  body        text,
  staff_id    uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  -- Ingest provenance (audit, not the dedupe key — see header).
  source_ref  text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  -- R8 idempotency: (phone→contact, timestamp, direction) + channel.
  -- Ingest MUST truncate occurred_at to the second before insert.
  CONSTRAINT crm_communications_dedupe_key UNIQUE (contact_id, channel, direction, occurred_at)
);
CREATE INDEX IF NOT EXISTS crm_communications_contact_idx  ON public.crm_communications (contact_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS crm_communications_lead_idx     ON public.crm_communications (lead_id);
CREATE INDEX IF NOT EXISTS crm_communications_occurred_idx ON public.crm_communications (occurred_at DESC);

-- Append-only enforcement: fires for EVERYONE, including service_role.
CREATE OR REPLACE FUNCTION public.crm_communications_no_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'crm_communications is append-only: % not allowed', TG_OP
    USING ERRCODE = '25001';
  RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS crm_communications_append_only ON public.crm_communications;
CREATE TRIGGER crm_communications_append_only
  BEFORE UPDATE OR DELETE ON public.crm_communications
  FOR EACH ROW EXECUTE FUNCTION public.crm_communications_no_mutation();

-- ── crm_followups ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.crm_followups (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  lead_id       uuid REFERENCES public.crm_leads(id) ON DELETE CASCADE,
  contact_id    uuid REFERENCES public.crm_contacts(id) ON DELETE CASCADE,
  CONSTRAINT crm_followups_one_subject CHECK (num_nonnulls(lead_id, contact_id) = 1),
  assignee_id   uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  due_at        timestamptz NOT NULL,
  -- due_rule=next_shift computes due_at against the staffer's shift
-- calendar (Carole: Wed 10–2, Sat 12–3 CT) in Phase 1 code.
  due_rule      text NOT NULL DEFAULT 'fixed' CHECK (due_rule IN ('fixed','next_shift')),
  priority      text NOT NULL DEFAULT 'normal' CHECK (priority IN ('low','normal','high','urgent')),
  note          text,
  done_at       timestamptz,
  snoozed_until timestamptz,
  recurrence    text,  -- e.g. 'daily' | 'weekly' | NULL
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS crm_followups_assignee_due_idx
  ON public.crm_followups (assignee_id, due_at) WHERE done_at IS NULL;
CREATE INDEX IF NOT EXISTS crm_followups_lead_idx    ON public.crm_followups (lead_id);
CREATE INDEX IF NOT EXISTS crm_followups_contact_idx ON public.crm_followups (contact_id);
-- Delegation model (Phase 0 RLS fix): the creator may assign follow-ups
-- to other staff (Carole, Joshua, Sunny) and still see/edit them.
ALTER TABLE public.crm_followups
  ADD COLUMN IF NOT EXISTS created_by uuid REFERENCES public.profiles(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS crm_followups_created_by_idx ON public.crm_followups (created_by);

-- ── funnel_entries (vendor/realtor keyword state machines) ─────
CREATE TABLE IF NOT EXISTS public.funnel_entries (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  contact_id         uuid NOT NULL REFERENCES public.crm_contacts(id) ON DELETE CASCADE,
  funnel             public.crm_funnel NOT NULL CHECK (funnel IN ('vendor','realtor')),
  keyword            text NOT NULL,  -- 'cleaner' | 'vendor' | 'jobs' | 'pro' | 'handyman' | 'lawn' | …
  stage              public.crm_funnel_stage NOT NULL DEFAULT 'keyword_received',
  keyword_received_at timestamptz NOT NULL DEFAULT now(),
  draft_attached_at  timestamptz,
  approved_at        timestamptz,
  sent_at            timestamptz,
  replied_at         timestamptz,
  onboarded_at       timestamptz,
  -- G3: no FK — drafts live in the SOP markdown until Phase 2.
  attached_draft_id  text,
  reply_text         text,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT funnel_entries_one_live UNIQUE (contact_id, funnel)
);
CREATE INDEX IF NOT EXISTS funnel_entries_stage_idx ON public.funnel_entries (funnel, stage);

-- ── event_tickets ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.event_tickets (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- G4: open text by convention ('nov7_2026', 'qa_oct20_2026', …) —
  -- events are unbounded; an enum would need a migration per event.
  event                 text NOT NULL,
  buyer_contact_id      uuid REFERENCES public.crm_contacts(id) ON DELETE SET NULL,
  tier                  text,
  amount_cents          integer,
  purchased_at          timestamptz NOT NULL DEFAULT now(),
  source                public.crm_source,
  source_detail         text,
  referred_by_profile_id uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
  -- Stripe webhook idempotency key (fed by webhook metadata, Phase 3).
  stripe_payment_intent_id text,
  created_at            timestamptz NOT NULL DEFAULT now()
);
-- Partial unique: multiple NULLs allowed, one row per real intent.
DROP INDEX IF EXISTS event_tickets_stripe_intent_idx;
CREATE UNIQUE INDEX event_tickets_stripe_intent_idx
  ON public.event_tickets (stripe_payment_intent_id)
  WHERE stripe_payment_intent_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS event_tickets_event_idx ON public.event_tickets (event);
CREATE INDEX IF NOT EXISTS event_tickets_buyer_idx ON public.event_tickets (buyer_contact_id);

-- ── scheduled_posts: social_drafts fields (§4, minus G2 redundancy)
ALTER TABLE public.scheduled_posts
  ADD COLUMN IF NOT EXISTS created_by     uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS needs_approval boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS approved_by    uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS approved_at    timestamptz;
-- (scheduled_for + author_id already exist — §4's "add scheduled_for"
-- is redundant. created_by = drafting staff user; author_id = post owner.)

-- ── profiles: promoted attribution (§5) ───────────────────────
ALTER TABLE public.profiles
  ADD COLUMN IF NOT EXISTS attribution_source  public.crm_source,
  ADD COLUMN IF NOT EXISTS attribution_at      timestamptz,
  ADD COLUMN IF NOT EXISTS attribution_post_id uuid REFERENCES public.feed_posts(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS utm_source          text,
  ADD COLUMN IF NOT EXISTS utm_medium          text,
  ADD COLUMN IF NOT EXISTS utm_campaign        text,
  ADD COLUMN IF NOT EXISTS utm_content         text;
-- G5: no backfill from onboarding_answers.heard_about_us here — the
-- legacy free-text mapping needs Jeremy's review (Phase 4).
CREATE INDEX IF NOT EXISTS profiles_attribution_source_idx ON public.profiles (attribution_source);

-- ── jobs: carry source/campaign_tag through conversion ─────────
-- (conversion code copies crm_leads.source/campaign_tag here; the
-- copy is explicit in code, not a trigger — see header.)
ALTER TABLE public.jobs
  ADD COLUMN IF NOT EXISTS source       public.crm_source,
  ADD COLUMN IF NOT EXISTS campaign_tag text,
  -- §5: post linkage on every intake — a job converted from a lead
  -- keeps the originating post for per-source revenue reporting.
  ADD COLUMN IF NOT EXISTS origin_post_id uuid REFERENCES public.feed_posts(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS utm_source   text,
  ADD COLUMN IF NOT EXISTS utm_medium   text,
  ADD COLUMN IF NOT EXISTS utm_campaign text,
  ADD COLUMN IF NOT EXISTS utm_content  text;
CREATE INDEX IF NOT EXISTS jobs_source_idx ON public.jobs (source);

-- ── vendors: vendor-intake attribution (§5 vendor-apply) ───────
ALTER TABLE public.vendors
  ADD COLUMN IF NOT EXISTS source         public.crm_source,
  ADD COLUMN IF NOT EXISTS source_detail  text,
  ADD COLUMN IF NOT EXISTS campaign_tag   text,
  ADD COLUMN IF NOT EXISTS origin_post_id uuid REFERENCES public.feed_posts(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS utm_source     text,
  ADD COLUMN IF NOT EXISTS utm_medium     text,
  ADD COLUMN IF NOT EXISTS utm_campaign   text,
  ADD COLUMN IF NOT EXISTS utm_content    text;

-- ── commissions: Phase 3 server-computation columns (stub only) ─
-- The client-side insert dies in this phase (app change); these
-- columns are where the won-time server computation will land.
ALTER TABLE public.commissions
  ADD COLUMN IF NOT EXISTS computed_at        timestamptz,
  ADD COLUMN IF NOT EXISTS computed_from_cents integer,
  ADD COLUMN IF NOT EXISTS rate               numeric,
  ADD COLUMN IF NOT EXISTS approved_by        uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS approved_at        timestamptz;
