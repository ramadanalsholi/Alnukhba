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
  primary key (organization_id, collection, id)
);

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
    values (coalesce(nullif(trim(p_name), ''), 'مطحن النخبة'))
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

alter table public.organizations enable row level security;

alter table public.organization_members enable row level security;

alter table public.app_records enable row level security;

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

create policy "members can view membership" on public.organization_members for
select to authenticated using (user_id = auth.uid ());

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

create policy "members can delete records" on public.app_records for delete to authenticated using (
    exists (
        select 1
        from public.organization_members m
        where
            m.organization_id = app_records.organization_id
            and m.user_id = auth.uid ()
    )
);

alter publication supabase_realtime add table public.app_records;