create extension if not exists pgcrypto;

create table if not exists public.organizations (
    id uuid primary key default gen_random_uuid (),
    name text not null,
    invite_code text not null unique default upper(
        substr(
            encode (gen_random_bytes (6), 'hex'),
            1,
            8
        )
    ),
    created_at timestamptz not null default now()
);

create table if not exists public.organization_members (
    organization_id uuid not null references public.organizations (id) on delete cascade,
    user_id uuid not null references auth.users (id) on delete cascade,
    role text not null default 'member' check (role in ('owner', 'member')),
    created_at timestamptz not null default now(),
    primary key (organization_id, user_id)
);

create table if not exists public.app_records (
  organization_id uuid not null references public.organizations(id) on delete cascade,
  collection text not null,
  id text not null,
  payload jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  constraint app_records_collection_check check (collection in (
    'invoices', 'inventory', 'inventoryMovements', 'customers', 'suppliers',
    'workers', 'attendance', 'treasury', 'expenses'
  )),
  primary key (organization_id, collection, id)
);

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'app_records_collection_check'
      and conrelid = 'public.app_records'::regclass
  ) then
    alter table public.app_records
      add constraint app_records_collection_check check (collection in (
        'invoices', 'inventory', 'inventoryMovements', 'customers', 'suppliers',
        'workers', 'attendance', 'treasury', 'expenses'
      ));
  end if;
end;
$$;

create index if not exists app_records_org_collection_updated_idx on public.app_records (
    organization_id,
    collection,
    updated_at desc
);

create or replace function public.set_app_record_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists app_records_updated_at on public.app_records;

create trigger app_records_updated_at
before update on public.app_records
for each row execute function public.set_app_record_updated_at();

-- Save all records belonging to one accounting voucher in a single transaction.
-- This prevents cash, contact-ledger, and invoice balances from being only partly saved.
create or replace function public.upsert_app_records_batch(p_organization_id uuid, p_records jsonb)
returns void
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  item jsonb;
  target_collection text;
  target_id text;
  target_payload jsonb;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;
  if p_organization_id is null or not exists (
    select 1 from public.organization_members m
    where m.organization_id = p_organization_id and m.user_id = auth.uid()
  ) then
    raise exception 'Organization access denied';
  end if;
  if jsonb_typeof(p_records) is distinct from 'array' then
    raise exception 'Records must be a JSON array';
  end if;

  for item in select value from jsonb_array_elements(p_records)
  loop
    target_collection := item->>'collection';
    target_id := item->>'id';
    target_payload := item->'payload';
    if target_collection is null or target_collection not in (
      'invoices', 'inventory', 'inventoryMovements', 'customers', 'suppliers',
      'workers', 'attendance', 'treasury', 'expenses'
    ) then
      raise exception 'Invalid record collection';
    end if;
    if target_id is null or length(trim(target_id)) = 0
       or jsonb_typeof(target_payload) is distinct from 'object'
       or target_payload->>'id' is distinct from target_id then
      raise exception 'Invalid record payload or id';
    end if;

    insert into public.app_records (organization_id, collection, id, payload)
    values (p_organization_id, target_collection, target_id, target_payload)
    on conflict (organization_id, collection, id)
    do update set payload = excluded.payload;
  end loop;
end;
$$;

revoke all on function public.upsert_app_records_batch(uuid, jsonb) from public, anon;
grant execute on function public.upsert_app_records_batch(uuid, jsonb) to authenticated;

create or replace function public.get_or_create_my_organization(p_name text, p_code text default '')
returns table (id uuid, organization_id uuid, name text, invite_code text)
language plpgsql
security definer
set search_path = public
as $$
declare
  target_id uuid;
  target_name text;
  target_code text;
  existing_member uuid;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  select om.organization_id into existing_member
  from public.organization_members om
  where om.user_id = auth.uid()
  limit 1;

  if existing_member is not null then
    select o.id, o.name, o.invite_code into target_id, target_name, target_code
    from public.organizations o where o.id = existing_member;
  elsif nullif(trim(p_code), '') is not null then
    select o.id, o.name, o.invite_code into target_id, target_name, target_code
    from public.organizations o where upper(o.invite_code) = upper(trim(p_code));
    if target_id is null then
      raise exception 'Invalid organization code';
    end if;
    insert into public.organization_members (organization_id, user_id, role)
    values (target_id, auth.uid(), 'member')
    on conflict do nothing;
  else
    insert into public.organizations (name)
    values (coalesce(nullif(trim(p_name), ''), 'شركة القصر'))
    returning organizations.id, organizations.name, organizations.invite_code
    into target_id, target_name, target_code;
    insert into public.organization_members (organization_id, user_id, role)
    values (target_id, auth.uid(), 'owner');
  end if;

  return query select target_id, target_id, target_name, target_code;
end;
$$;

grant
execute on function public.get_or_create_my_organization (text, text) to authenticated;
revoke all on function public.get_or_create_my_organization (text, text) from public, anon;

alter table public.organizations enable row level security;

alter table public.organization_members enable row level security;

alter table public.app_records enable row level security;

drop policy if exists "members can view their organizations" on public.organizations;
create policy "members can view their organizations" on public.organizations for
select to authenticated using (
        exists (
            select 1
            from public.organization_members m
            where
                m.organization_id = organizations.id
                and m.user_id = auth.uid ()
        )
    );

drop policy if exists "members can view membership" on public.organization_members;
create policy "members can view membership" on public.organization_members for
select to authenticated using (user_id = auth.uid ());

drop policy if exists "members can read records" on public.app_records;
create policy "members can read records" on public.app_records for
select to authenticated using (
        exists (
            select 1
            from public.organization_members m
            where
                m.organization_id = app_records.organization_id
                and m.user_id = auth.uid ()
        )
    );

drop policy if exists "members can insert records" on public.app_records;
create policy "members can insert records" on public.app_records for
insert
    to authenticated
with
    check (
        exists (
            select 1
            from public.organization_members m
            where
                m.organization_id = app_records.organization_id
                and m.user_id = auth.uid ()
        )
    );

drop policy if exists "members can update records" on public.app_records;
create policy "members can update records" on public.app_records for
update to authenticated using (
    exists (
        select 1
        from public.organization_members m
        where
            m.organization_id = app_records.organization_id
            and m.user_id = auth.uid ()
    )
)
with
    check (
        exists (
            select 1
            from public.organization_members m
            where
                m.organization_id = app_records.organization_id
                and m.user_id = auth.uid ()
        )
    );

drop policy if exists "members can delete records" on public.app_records;
drop policy if exists "owners can delete records" on public.app_records;
create policy "owners can delete records" on public.app_records for delete to authenticated using (
    exists (
        select 1
        from public.organization_members m
        where m.organization_id = app_records.organization_id
          and m.user_id = auth.uid ()
          and m.role = 'owner'
    )
);

alter table public.app_records replica identity full;

do $$
begin
  if not exists (
    select 1
    from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'app_records'
  ) then
    alter publication supabase_realtime add table public.app_records;
  end if;
end;
$$;
