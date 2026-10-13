-- ============================================================
-- CRM Phase 0c — contact visibility RLS (R1: the #1 landmine)
-- ============================================================
--
-- THREAT MODEL: a `sales` staff-role user (Joshua, Carole, Sunny)
-- must NEVER SELECT an owner_only contact (e.g. Kyle Glaeser —
-- Jeremy-owned, $2,044.98 invoice) via any path: list, search,
-- export, or direct Supabase REST. The existing
-- profiles_authenticated_read policy is USING(true) for every
-- authenticated user and is INTENTIONALLY left alone — public pages
-- (/vendors/[slug], /listings/[id]) render through server components
-- with session cookies and depend on it. The CRM contact book is a
-- NEW surface (crm_contacts et al.), so the hole is closed here at
-- birth without touching profiles at all.
--
-- ENFORCEMENT LAYERS:
--   1. RLS below (the backstop — binds direct REST + client queries).
--   2. Phase 1+ API routes must ALSO filter in code (service_role
--      bypasses RLS); RLS alone is not the whole story.
--
-- VISIBILITY RULE (crm_contacts):
--   SELECT iff: visibility='team' (any authenticated staff),
--            OR owner_id = auth.uid() (the owner themself),
--            OR privileged (profiles.role='admin' / super_admin /
--               support staff via crm_is_privileged()).
--   A sales-role user is simply "authenticated, not owner, not
--   privileged" → owner_only rows are invisible. There is no
--   sales-specific carve-out to get wrong.
-- ============================================================

-- Privilege helper: SECURITY DEFINER so it can read profiles /
-- staff_roles past their own RLS inside policy checks.
CREATE OR REPLACE FUNCTION public.crm_is_privileged()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
           SELECT 1 FROM public.profiles
           WHERE id = auth.uid() AND role = 'admin'
         )
      OR EXISTS (
           SELECT 1 FROM public.staff_roles
           WHERE user_id = auth.uid()
             AND active
             AND role IN ('super_admin', 'support')
         );
$$;
GRANT EXECUTE ON FUNCTION public.crm_is_privileged() TO authenticated;

-- ── dnc_registry (privileged only; table reconciled in phase0a) ──
-- All runtime access is via the service-role admin client (bypasses
-- RLS). This policy exists so support/admin tooling on an authenticated
-- session can read/write the registry; everyone else gets nothing.
DROP POLICY IF EXISTS "dnc_registry_privileged_only" ON public.dnc_registry;
CREATE POLICY "dnc_registry_privileged_only"
  ON public.dnc_registry FOR ALL TO authenticated
  USING (public.crm_is_privileged())
  WITH CHECK (public.crm_is_privileged());

-- ── crm_contacts ─────────────────────────────────────────────
ALTER TABLE public.crm_contacts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "crm_contacts_select" ON public.crm_contacts;
CREATE POLICY "crm_contacts_select"
  ON public.crm_contacts FOR SELECT TO authenticated
  USING (
    visibility = 'team'
    OR owner_id = auth.uid()
    OR public.crm_is_privileged()
  );

DROP POLICY IF EXISTS "crm_contacts_insert" ON public.crm_contacts;
CREATE POLICY "crm_contacts_insert"
  ON public.crm_contacts FOR INSERT TO authenticated
  WITH CHECK (
    -- Non-privileged inserts must stamp owner_id = the inserting user,
    -- regardless of visibility: a team-visible row with someone else's
    -- owner_id would be owner_id spoofing. Seeding Jeremy's owner_only
    -- list stays a privileged op (Phase 3, Jeremy reviews the list).
    owner_id = auth.uid()
    OR public.crm_is_privileged()
  );

DROP POLICY IF EXISTS "crm_contacts_update" ON public.crm_contacts;
CREATE POLICY "crm_contacts_update"
  ON public.crm_contacts FOR UPDATE TO authenticated
  USING (owner_id = auth.uid() OR public.crm_is_privileged())
  WITH CHECK (owner_id = auth.uid() OR public.crm_is_privileged());

DROP POLICY IF EXISTS "crm_contacts_delete" ON public.crm_contacts;
CREATE POLICY "crm_contacts_delete"
  ON public.crm_contacts FOR DELETE TO authenticated
  USING (owner_id = auth.uid() OR public.crm_is_privileged());

-- ── crm_leads (revived from public.leads) ─────────────────────
ALTER TABLE public.crm_leads ENABLE ROW LEVEL SECURITY;

-- Drop the dead table's original policies (they reference the
-- pre-rename column; the rename propagated, but the model is replaced).
DROP POLICY IF EXISTS "leads_agent_own" ON public.crm_leads;
DROP POLICY IF EXISTS "leads_admin_all" ON public.crm_leads;
DROP POLICY IF EXISTS "crm_leads_select" ON public.crm_leads;
DROP POLICY IF EXISTS "crm_leads_insert" ON public.crm_leads;
DROP POLICY IF EXISTS "crm_leads_update" ON public.crm_leads;
DROP POLICY IF EXISTS "crm_leads_delete" ON public.crm_leads;

-- A lead is visible iff its owner, privileged, or its linked contact
-- is team-visible. Leads with no contact yet: owner/privileged only.
CREATE POLICY "crm_leads_select"
  ON public.crm_leads FOR SELECT TO authenticated
  USING (
    owner_id = auth.uid()
    OR public.crm_is_privileged()
    OR EXISTS (
      SELECT 1 FROM public.crm_contacts c
      WHERE c.id = crm_leads.contact_id AND c.visibility = 'team'
    )
  );

CREATE POLICY "crm_leads_insert"
  ON public.crm_leads FOR INSERT TO authenticated
  WITH CHECK (owner_id = auth.uid() OR public.crm_is_privileged());

CREATE POLICY "crm_leads_update"
  ON public.crm_leads FOR UPDATE TO authenticated
  USING (owner_id = auth.uid() OR public.crm_is_privileged())
  WITH CHECK (owner_id = auth.uid() OR public.crm_is_privileged());

CREATE POLICY "crm_leads_delete"
  ON public.crm_leads FOR DELETE TO authenticated
  USING (owner_id = auth.uid() OR public.crm_is_privileged());

-- ── crm_communications (append-only: SELECT + INSERT only) ────
ALTER TABLE public.crm_communications ENABLE ROW LEVEL SECURITY;

-- Visibility follows the parent contact: team contact → team sees the
-- thread; owner_only contact → owner + privileged only. This is what
-- keeps a sales user from reading Kyle Glaeser's thread even though
-- they can read other threads.
DROP POLICY IF EXISTS "crm_communications_select" ON public.crm_communications;
CREATE POLICY "crm_communications_select"
  ON public.crm_communications FOR SELECT TO authenticated
  USING (
    public.crm_is_privileged()
    OR EXISTS (
      SELECT 1 FROM public.crm_contacts c
      WHERE c.id = crm_communications.contact_id
        AND (c.visibility = 'team' OR c.owner_id = auth.uid())
    )
  );

DROP POLICY IF EXISTS "crm_communications_insert" ON public.crm_communications;
CREATE POLICY "crm_communications_insert"
  ON public.crm_communications FOR INSERT TO authenticated
  WITH CHECK (
    public.crm_is_privileged()
    OR EXISTS (
      SELECT 1 FROM public.crm_contacts c
      WHERE c.id = crm_communications.contact_id
        AND (c.visibility = 'team' OR c.owner_id = auth.uid())
    )
  );
-- No UPDATE/DELETE policies (default-deny) AND the phase0b trigger
-- raises on UPDATE/DELETE for every role incl. service_role.

-- ── crm_followups ─────────────────────────────────────────────
-- DELEGATION MODEL (Gemini lane): the creator may assign a follow-up
-- to another staffer and still see/edit it. ChatGPT's original
-- assignee-only INSERT made "Jeremy creates a follow-up and assigns
-- it to Carole" impossible for a non-privileged creator — a Phase 1
-- functional bug.
--
-- PII GATE (R1): the follow-up note can carry PII (e.g. Jeremy's
-- "Call Kyle re: $2,044.98 invoice" assigned to Carole). SELECT is
-- additionally gated on the LINKED CONTACT's visibility: an assignee
-- who cannot see the contact cannot read the note. Privileged users
-- and the contact's owner are unaffected.
ALTER TABLE public.crm_followups ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "crm_followups_select" ON public.crm_followups;
CREATE POLICY "crm_followups_select"
  ON public.crm_followups FOR SELECT TO authenticated
  USING (
    (
      public.crm_is_privileged()
      OR crm_followups.created_by = auth.uid()
      OR crm_followups.assignee_id = auth.uid()
    )
    AND (
      public.crm_is_privileged()
      OR EXISTS (
        SELECT 1 FROM public.crm_contacts c
        WHERE c.id = COALESCE(
                crm_followups.contact_id,
                (SELECT l.contact_id
                   FROM public.crm_leads l
                  WHERE l.id = crm_followups.lead_id)
              )
          AND (c.visibility = 'team' OR c.owner_id = auth.uid())
      )
      OR (
        -- Contact-less lead follow-up: the lead owner OR the follow-up's
        -- creator may see it (a creator must read what they created).
        crm_followups.contact_id IS NULL
        AND (SELECT l.contact_id FROM public.crm_leads l
             WHERE l.id = crm_followups.lead_id) IS NULL
        AND (
          crm_followups.created_by = auth.uid()
          OR EXISTS (
            SELECT 1 FROM public.crm_leads l
            WHERE l.id = crm_followups.lead_id
              AND l.owner_id = auth.uid()
          )
        )
      )
    )
  );

-- INSERT: creator may assign to anyone (delegation); the row must be
-- stamped with created_by = the inserting user (or privileged). The
-- contact-visibility gate mirrors SELECT so a row can't be created on
-- an owner_only contact the creator cannot see.
DROP POLICY IF EXISTS "crm_followups_insert" ON public.crm_followups;
CREATE POLICY "crm_followups_insert"
  ON public.crm_followups FOR INSERT TO authenticated
  WITH CHECK (
    (
      crm_followups.created_by = auth.uid()
      OR public.crm_is_privileged()
    )
    AND (
      public.crm_is_privileged()
      OR EXISTS (
        SELECT 1 FROM public.crm_contacts c
        WHERE c.id = COALESCE(
                crm_followups.contact_id,
                (SELECT l.contact_id
                   FROM public.crm_leads l
                  WHERE l.id = crm_followups.lead_id)
              )
          AND (c.visibility = 'team' OR c.owner_id = auth.uid())
      )
      OR (
        -- Contact-less lead follow-up: the follow-up's creator or the
        -- lead owner may create it.
        crm_followups.contact_id IS NULL
        AND (SELECT l.contact_id FROM public.crm_leads l
             WHERE l.id = crm_followups.lead_id) IS NULL
        AND (
          crm_followups.created_by = auth.uid()
          OR EXISTS (
            SELECT 1 FROM public.crm_leads l
            WHERE l.id = crm_followups.lead_id
              AND l.owner_id = auth.uid()
          )
        )
      )
    )
  );

-- UPDATE: creator, assignee, or privileged; same contact-visibility
-- gate as SELECT so notes stay sealed.
DROP POLICY IF EXISTS "crm_followups_update" ON public.crm_followups;
CREATE POLICY "crm_followups_update"
  ON public.crm_followups FOR UPDATE TO authenticated
  USING (
    (
      public.crm_is_privileged()
      OR crm_followups.created_by = auth.uid()
      OR crm_followups.assignee_id = auth.uid()
    )
    AND (
      public.crm_is_privileged()
      OR EXISTS (
        SELECT 1 FROM public.crm_contacts c
        WHERE c.id = COALESCE(
                crm_followups.contact_id,
                (SELECT l.contact_id
                   FROM public.crm_leads l
                  WHERE l.id = crm_followups.lead_id)
              )
          AND (c.visibility = 'team' OR c.owner_id = auth.uid())
      )
      OR (
        -- Contact-less lead follow-up: the lead owner OR the follow-up's
        -- creator may see it (a creator must read what they created).
        crm_followups.contact_id IS NULL
        AND (SELECT l.contact_id FROM public.crm_leads l
             WHERE l.id = crm_followups.lead_id) IS NULL
        AND (
          crm_followups.created_by = auth.uid()
          OR EXISTS (
            SELECT 1 FROM public.crm_leads l
            WHERE l.id = crm_followups.lead_id
              AND l.owner_id = auth.uid()
          )
        )
      )
    )
  )
  -- WITH CHECK mirrors the SELECT gate (role + linked-contact
  -- visibility) so a row can't be repointed at an owner_only contact
  -- the editor cannot see.
  WITH CHECK (
    (
      public.crm_is_privileged()
      OR crm_followups.created_by = auth.uid()
      OR crm_followups.assignee_id = auth.uid()
    )
    AND (
      public.crm_is_privileged()
      OR EXISTS (
        SELECT 1 FROM public.crm_contacts c
        WHERE c.id = COALESCE(
                crm_followups.contact_id,
                (SELECT l.contact_id
                   FROM public.crm_leads l
                  WHERE l.id = crm_followups.lead_id)
              )
          AND (c.visibility = 'team' OR c.owner_id = auth.uid())
      )
      OR (
        -- Contact-less lead follow-up: the follow-up's creator or the
        -- lead owner may keep it pointed there.
        crm_followups.contact_id IS NULL
        AND (SELECT l.contact_id FROM public.crm_leads l
             WHERE l.id = crm_followups.lead_id) IS NULL
        AND (
          crm_followups.created_by = auth.uid()
          OR EXISTS (
            SELECT 1 FROM public.crm_leads l
            WHERE l.id = crm_followups.lead_id
              AND l.owner_id = auth.uid()
          )
        )
      )
    )
  );

-- DELETE: creator or privileged only (an assignee completing a
-- follow-up sets done_at; they do not delete the row).
DROP POLICY IF EXISTS "crm_followups_delete" ON public.crm_followups;
CREATE POLICY "crm_followups_delete"
  ON public.crm_followups FOR DELETE TO authenticated
  USING (
    public.crm_is_privileged()
    OR crm_followups.created_by = auth.uid()
  );

-- ── funnel_entries ────────────────────────────────────────────
ALTER TABLE public.funnel_entries ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "funnel_entries_select" ON public.funnel_entries;
CREATE POLICY "funnel_entries_select"
  ON public.funnel_entries FOR SELECT TO authenticated
  USING (
    public.crm_is_privileged()
    OR EXISTS (
      SELECT 1 FROM public.crm_contacts c
      WHERE c.id = funnel_entries.contact_id
        AND (c.visibility = 'team' OR c.owner_id = auth.uid())
    )
  );

DROP POLICY IF EXISTS "funnel_entries_write" ON public.funnel_entries;
CREATE POLICY "funnel_entries_write"
  ON public.funnel_entries FOR ALL TO authenticated
  USING (
    public.crm_is_privileged()
    OR EXISTS (
      SELECT 1 FROM public.crm_contacts c
      WHERE c.id = funnel_entries.contact_id
        AND (c.visibility = 'team' OR c.owner_id = auth.uid())
    )
  )
  WITH CHECK (
    public.crm_is_privileged()
    OR EXISTS (
      SELECT 1 FROM public.crm_contacts c
      WHERE c.id = funnel_entries.contact_id
        AND (c.visibility = 'team' OR c.owner_id = auth.uid())
    )
  );

-- ── event_tickets (buyer PII + money: privileged only) ─────────
ALTER TABLE public.event_tickets ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "event_tickets_privileged" ON public.event_tickets;
CREATE POLICY "event_tickets_privileged"
  ON public.event_tickets FOR ALL TO authenticated
  USING (public.crm_is_privileged())
  WITH CHECK (public.crm_is_privileged());
