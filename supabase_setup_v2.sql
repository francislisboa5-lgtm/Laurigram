-- LAURIGRAM: endurecimento e preparação para Supabase Auth + media
-- Executar DEPOIS de supabase_schema_inicial.sql no SQL Editor do Supabase.
-- Não contém chaves nem credenciais.

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;
grant usage on schema private to postgres, service_role;

-- 1) Privilégios administrativos apenas no backend / SQL Editor.
create table if not exists private.user_roles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('admin','moderator')),
  created_at timestamptz not null default now()
);
revoke all on private.user_roles from public, anon, authenticated;
grant select, insert, update, delete on private.user_roles to service_role;

create or replace function public.is_admin()
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1 from private.user_roles r
    where r.user_id = auth.uid() and r.role = 'admin'
  );
$$;
revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to authenticated;

-- 2) Retira o selo da tabela pública: utilizador nunca pode auto-verificar-se.
create table if not exists private.profile_verifications (
  user_id uuid primary key references auth.users(id) on delete cascade,
  gold_verified_until timestamptz not null,
  verified_by uuid references auth.users(id),
  updated_at timestamptz not null default now()
);
revoke all on private.profile_verifications from public, anon, authenticated;
grant select, insert, update, delete on private.profile_verifications to service_role;

do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema='public' and table_name='profiles' and column_name='gold_verified_until'
  ) then
    execute $m$
      insert into private.profile_verifications(user_id, gold_verified_until)
      select id, gold_verified_until from public.profiles
      where gold_verified_until is not null
      on conflict (user_id) do update
      set gold_verified_until = excluded.gold_verified_until,
          updated_at = now()
    $m$;
    alter table public.profiles drop column gold_verified_until;
  end if;
end $$;

create or replace function public.is_gold_verified(target_user_id uuid)
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1 from private.profile_verifications v
    where v.user_id = target_user_id and v.gold_verified_until > now()
  );
$$;
revoke all on function public.is_gold_verified(uuid) from public;
grant execute on function public.is_gold_verified(uuid) to anon, authenticated;

-- 3) Cria automaticamente o perfil após signup do Supabase Auth.
create or replace function public.handle_new_user()
returns trigger
language plpgsql security definer
set search_path = ''
as $$
declare
  base_username text;
  candidate text;
  display_name text;
begin
  base_username := regexp_replace(
    coalesce(new.raw_user_meta_data->>'username', 'membro_' || left(new.id::text, 8)),
    '[^a-zA-Z0-9_.]', '', 'g'
  );
  if base_username = '' then
    base_username := 'membro_' || left(new.id::text, 8);
  end if;
  candidate := left(base_username, 24);
  while exists (select 1 from public.profiles p where p.username = candidate) loop
    candidate := left(base_username, 16) || '_' || left(gen_random_uuid()::text, 7);
  end loop;
  display_name := coalesce(
    nullif(new.raw_user_meta_data->>'full_name',''),
    nullif(new.raw_user_meta_data->>'name',''),
    split_part(coalesce(new.email, new.phone, 'Novo membro'), '@', 1)
  );
  insert into public.profiles(id, username, full_name)
  values (new.id, candidate, display_name)
  on conflict (id) do nothing;
  return new;
end;
$$;

 drop trigger if exists on_auth_user_created_laurigram on auth.users;
create trigger on_auth_user_created_laurigram
after insert on auth.users
for each row execute procedure public.handle_new_user();

-- 4) Mídia de publicações e stories.
create table if not exists public.post_media (
  id uuid primary key default gen_random_uuid(),
  post_id uuid not null references public.posts(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  media_path text not null unique,
  position smallint not null default 0 check (position between 0 and 7),
  created_at timestamptz not null default now()
);
create index if not exists post_media_post_idx on public.post_media(post_id, position);

create table if not exists public.stories (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  media_path text not null,
  media_type text not null default 'image' check (media_type = 'image'),
  expires_at timestamptz not null default (now() + interval '24 hours'),
  created_at timestamptz not null default now()
);
create index if not exists stories_active_idx on public.stories(expires_at desc);

alter table public.post_media enable row level security;
alter table public.stories enable row level security;

-- 5) RLS e privilégios mínimos. Revogar primeiro evita permissões herdadas amplas.
alter table public.profiles enable row level security;
alter table public.posts enable row level security;
alter table public.post_likes enable row level security;
alter table public.comments enable row level security;
alter table public.friend_requests enable row level security;
alter table public.follows enable row level security;
alter table public.pages enable row level security;
alter table public.market_listings enable row level security;
alter table public.payment_requests enable row level security;
alter table public.gifts enable row level security;
alter table public.withdrawal_requests enable row level security;
alter table public.sponsorship_campaigns enable row level security;
alter table public.music_catalog enable row level security;
revoke all on public.profiles, public.posts, public.post_likes, public.comments,
  public.friend_requests, public.follows, public.pages, public.market_listings,
  public.post_media, public.stories, public.music_catalog
from public, anon, authenticated;

-- Perfis: leitura pública; utilizador pode alterar apenas campos não sensíveis.
grant select on public.profiles to anon, authenticated;
grant update (username, full_name, bio, avatar_url, cover_url) on public.profiles to authenticated;

-- Feed e interacções.
grant select on public.posts, public.post_likes, public.comments to anon, authenticated;
grant insert (user_id, body) on public.posts to authenticated;
grant update (body) on public.posts to authenticated;
grant delete on public.posts to authenticated;
grant insert (post_id, user_id) on public.post_likes to authenticated;
grant delete on public.post_likes to authenticated;
grant insert (post_id, user_id, body) on public.comments to authenticated;
grant delete on public.comments to authenticated;

-- Amizades e seguidores.
grant select on public.friend_requests, public.follows to authenticated;
grant insert (sender_id, receiver_id) on public.friend_requests to authenticated;
grant update (status) on public.friend_requests to authenticated;
grant insert (follower_id, following_id) on public.follows to authenticated;
grant delete on public.follows to authenticated;

-- Páginas e marketplace.
grant select on public.pages, public.market_listings to anon, authenticated;
grant insert (owner_id, name, description) on public.pages to authenticated;
grant update (name, description) on public.pages to authenticated;
grant delete on public.pages to authenticated;
grant insert (seller_id, title, description, price_kz) on public.market_listings to authenticated;
grant update (title, description, price_kz, status) on public.market_listings to authenticated;
grant delete on public.market_listings to authenticated;

-- Mídia: ficheiros em bucket público para leitura social; escrita limitada à pasta do dono.
grant select on public.post_media, public.stories to anon, authenticated;
grant insert (post_id, user_id, media_path, position) on public.post_media to authenticated;
grant delete on public.post_media to authenticated;
grant insert (user_id, media_path, media_type) on public.stories to authenticated;
grant delete on public.stories to authenticated;

drop policy if exists "profiles_insert_self" on public.profiles;
drop policy if exists "profiles_update_self" on public.profiles;
create policy "profiles_update_self_safe" on public.profiles
  for update to authenticated using (auth.uid() = id) with check (auth.uid() = id);

-- Recria/garante políticas essenciais com escopo explícito.
drop policy if exists "posts_read" on public.posts;
create policy "posts_read_public" on public.posts for select to anon, authenticated using (true);
drop policy if exists "posts_insert_self" on public.posts;
create policy "posts_insert_self_safe" on public.posts for insert to authenticated with check (auth.uid() = user_id);
drop policy if exists "posts_update_owner" on public.posts;
create policy "posts_update_owner_safe" on public.posts for update to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
drop policy if exists "posts_delete_owner" on public.posts;
create policy "posts_delete_owner_safe" on public.posts for delete to authenticated using (auth.uid() = user_id);

drop policy if exists "likes_read" on public.post_likes;
create policy "likes_read_public" on public.post_likes for select to anon, authenticated using (true);
drop policy if exists "likes_insert_self" on public.post_likes;
create policy "likes_insert_self_safe" on public.post_likes for insert to authenticated with check (auth.uid() = user_id);
drop policy if exists "likes_delete_self" on public.post_likes;
create policy "likes_delete_self_safe" on public.post_likes for delete to authenticated using (auth.uid() = user_id);

drop policy if exists "comments_read" on public.comments;
create policy "comments_read_public" on public.comments for select to anon, authenticated using (true);
drop policy if exists "comments_insert_self" on public.comments;
create policy "comments_insert_self_safe" on public.comments for insert to authenticated with check (auth.uid() = user_id);
drop policy if exists "comments_delete_self" on public.comments;
create policy "comments_delete_self_safe" on public.comments for delete to authenticated using (auth.uid() = user_id);

drop policy if exists "friend_requests_participants_read" on public.friend_requests;
create policy "friend_requests_participants_read_safe" on public.friend_requests for select to authenticated
  using (auth.uid() = sender_id or auth.uid() = receiver_id);
drop policy if exists "friend_requests_sender_insert" on public.friend_requests;
create policy "friend_requests_sender_insert_safe" on public.friend_requests for insert to authenticated
  with check (auth.uid() = sender_id and sender_id <> receiver_id);
drop policy if exists "friend_requests_receiver_update" on public.friend_requests;
create policy "friend_requests_receiver_update_safe" on public.friend_requests for update to authenticated
  using (auth.uid() = receiver_id and status = 'pending')
  with check (auth.uid() = receiver_id and status in ('accepted','declined'));

drop policy if exists "follows_read" on public.follows;
create policy "follows_read_public" on public.follows for select to anon, authenticated using (true);
drop policy if exists "follows_insert_self" on public.follows;
create policy "follows_insert_self_safe" on public.follows for insert to authenticated with check (auth.uid() = follower_id and follower_id <> following_id);
drop policy if exists "follows_delete_self" on public.follows;
create policy "follows_delete_self_safe" on public.follows for delete to authenticated using (auth.uid() = follower_id);

drop policy if exists "pages_read" on public.pages;
create policy "pages_read_public" on public.pages for select to anon, authenticated using (true);
drop policy if exists "pages_owner_insert" on public.pages;
create policy "pages_owner_insert_safe" on public.pages for insert to authenticated with check (auth.uid() = owner_id);
drop policy if exists "pages_owner_update" on public.pages;
create policy "pages_owner_update_safe" on public.pages for update to authenticated using (auth.uid() = owner_id) with check (auth.uid() = owner_id);
drop policy if exists "market_read" on public.market_listings;
create policy "market_read_active" on public.market_listings for select to anon, authenticated using (status = 'active' or auth.uid() = seller_id);
drop policy if exists "market_insert_self" on public.market_listings;
create policy "market_insert_self_safe" on public.market_listings for insert to authenticated with check (auth.uid() = seller_id);
drop policy if exists "market_update_self" on public.market_listings;
create policy "market_update_self_safe" on public.market_listings for update to authenticated using (auth.uid() = seller_id) with check (auth.uid() = seller_id);
drop policy if exists "market_delete_self" on public.market_listings;
create policy "market_delete_self_safe" on public.market_listings for delete to authenticated using (auth.uid() = seller_id);

-- Só é possível anexar media a publicações do próprio utilizador.
drop policy if exists "post_media_read" on public.post_media;
create policy "post_media_read_public" on public.post_media for select to anon, authenticated using (true);
drop policy if exists "post_media_insert_owner" on public.post_media;
create policy "post_media_insert_owner" on public.post_media for insert to authenticated
  with check (auth.uid() = user_id and exists (
    select 1 from public.posts p where p.id = post_id and p.user_id = auth.uid()
  ));
drop policy if exists "post_media_delete_owner" on public.post_media;
create policy "post_media_delete_owner" on public.post_media for delete to authenticated using (auth.uid() = user_id);

drop policy if exists "stories_read_active" on public.stories;
create policy "stories_read_active_safe" on public.stories for select to anon, authenticated using (expires_at > now());
drop policy if exists "stories_insert_self" on public.stories;
create policy "stories_insert_self_safe" on public.stories for insert to authenticated with check (auth.uid() = user_id);
drop policy if exists "stories_delete_self" on public.stories;
create policy "stories_delete_self_safe" on public.stories for delete to authenticated using (auth.uid() = user_id);

-- 6) Música: leitura apenas de faixas aprovadas e licenciadas para Angola ou mundo.
grant select on public.music_catalog to anon, authenticated;
drop policy if exists "music_read_approved" on public.music_catalog;
create policy "music_read_approved_safe" on public.music_catalog for select to anon, authenticated using (
  review_status = 'approved'
  and license_starts_at <= now()
  and (license_ends_at is null or license_ends_at > now())
  and ('ANG' = any(allowed_territories) or '*' = any(allowed_territories))
);

-- 7) Tabelas financeiras/admin: nenhum acesso directo do navegador.
revoke all on public.payment_requests, public.gifts, public.withdrawal_requests,
  public.sponsorship_campaigns from public, anon, authenticated;
grant select, insert, update, delete on public.payment_requests, public.gifts,
  public.withdrawal_requests, public.sponsorship_campaigns to service_role;

-- 8) Bucket de imagens sociais. Bucket público para leitura de publicações/stories;
-- uploads e remoções continuam limitados à pasta UUID do próprio utilizador.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('laurigram-media', 'laurigram-media', true, 10485760,
        array['image/jpeg','image/png','image/webp'])
on conflict (id) do update set public = excluded.public,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "laurigram_media_insert_own_folder" on storage.objects;
create policy "laurigram_media_insert_own_folder" on storage.objects
for insert to authenticated with check (
  bucket_id = 'laurigram-media'
  and (storage.foldername(name))[1] = auth.uid()::text
);
drop policy if exists "laurigram_media_update_own_folder" on storage.objects;
create policy "laurigram_media_update_own_folder" on storage.objects
for update to authenticated using (
  bucket_id = 'laurigram-media'
  and (storage.foldername(name))[1] = auth.uid()::text
) with check (
  bucket_id = 'laurigram-media'
  and (storage.foldername(name))[1] = auth.uid()::text
);
drop policy if exists "laurigram_media_delete_own_folder" on storage.objects;
create policy "laurigram_media_delete_own_folder" on storage.objects
for delete to authenticated using (
  bucket_id = 'laurigram-media'
  and (storage.foldername(name))[1] = auth.uid()::text
);

-- 9) Regras contabilísticas dos presentes: arredondamento para baixo ao criador;
-- o resto fica para a plataforma. Ex.: 53 Kz -> 37 + 16 Kz.
do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'gifts_split_70_30_check') then
    alter table public.gifts add constraint gifts_split_70_30_check check (
      creator_amount_kz = floor(amount_kz * 0.70)::bigint
      and platform_fee_kz = amount_kz - creator_amount_kz
    );
  end if;
end $$;

-- 10) Estatísticas de visualização mantidas apenas pelo backend confiável.
create table if not exists private.post_view_totals (
  post_id uuid primary key references public.posts(id) on delete cascade,
  views bigint not null default 0 check (views >= 0),
  updated_at timestamptz not null default now()
);
revoke all on private.post_view_totals from public, anon, authenticated;
grant select, insert, update, delete on private.post_view_totals to service_role;

create or replace function public.creator_meets_monetization_requirements(target_user_id uuid)
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select
    public.is_gold_verified(target_user_id)
    and (select count(*) from public.follows f where f.following_id = target_user_id) >= 5000
    and coalesce((
      select sum(v.views)
      from private.post_view_totals v
      join public.posts p on p.id = v.post_id
      where p.user_id = target_user_id
    ), 0) >= 1000000;
$$;
revoke all on function public.creator_meets_monetization_requirements(uuid) from public;
grant execute on function public.creator_meets_monetization_requirements(uuid) to authenticated;

-- Nota: inserir o primeiro administrador manualmente no SQL Editor, após confirmar
-- o UUID correcto do dono: insert into private.user_roles(user_id,role) values ('UUID', 'admin');
-- Nunca criar um botão público de registo de administrador.
