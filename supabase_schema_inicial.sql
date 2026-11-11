-- LAURIGRAM / esquema inicial Supabase
-- Executar no SQL Editor de um projecto novo. Rever políticas antes de produção.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
 id uuid primary key references auth.users(id) on delete cascade,
 username text unique not null,
 full_name text not null,
 bio text default '',
 avatar_url text,
 cover_url text,
 gold_verified_until timestamptz,
 created_at timestamptz not null default now()
);
create table if not exists public.posts (
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null references public.profiles(id) on delete cascade,
 body text not null check (char_length(body) <= 5000),
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now()
);
create table if not exists public.post_likes (
 post_id uuid not null references public.posts(id) on delete cascade,
 user_id uuid not null references public.profiles(id) on delete cascade,
 created_at timestamptz not null default now(),
 primary key(post_id,user_id)
);
create table if not exists public.comments (
 id uuid primary key default gen_random_uuid(),
 post_id uuid not null references public.posts(id) on delete cascade,
 user_id uuid not null references public.profiles(id) on delete cascade,
 body text not null check (char_length(body) between 1 and 2000),
 created_at timestamptz not null default now()
);
create table if not exists public.friend_requests (
 id uuid primary key default gen_random_uuid(),
 sender_id uuid not null references public.profiles(id) on delete cascade,
 receiver_id uuid not null references public.profiles(id) on delete cascade,
 status text not null default 'pending' check(status in ('pending','accepted','declined','cancelled')),
 created_at timestamptz not null default now(),
 unique(sender_id,receiver_id),
 check(sender_id <> receiver_id)
);
create table if not exists public.follows (
 follower_id uuid not null references public.profiles(id) on delete cascade,
 following_id uuid not null references public.profiles(id) on delete cascade,
 created_at timestamptz not null default now(),
 primary key(follower_id,following_id),
 check(follower_id <> following_id)
);
create table if not exists public.pages (
 id uuid primary key default gen_random_uuid(),
 owner_id uuid not null references public.profiles(id) on delete cascade,
 name text not null,
 description text default '',
 created_at timestamptz not null default now()
);
create table if not exists public.market_listings (
 id uuid primary key default gen_random_uuid(),
 seller_id uuid not null references public.profiles(id) on delete cascade,
 title text not null,
 description text default '',
 price_kz bigint not null check(price_kz >= 0),
 status text not null default 'active' check(status in ('active','sold','removed')),
 created_at timestamptz not null default now()
);
create table if not exists public.payment_requests (
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null references public.profiles(id) on delete cascade,
 product_type text not null check(product_type in ('gold_badge','page_sponsorship')),
 amount_kz bigint not null check(amount_kz > 0),
 reference text unique not null,
 status text not null default 'pending' check(status in ('pending','confirmed','rejected','expired')),
 created_at timestamptz not null default now(),
 reviewed_at timestamptz
);
create table if not exists public.gifts (
 id uuid primary key default gen_random_uuid(),
 sender_id uuid not null references public.profiles(id),
 creator_id uuid not null references public.profiles(id),
 gift_type text not null check(gift_type in ('flower','heart','treasure')),
 amount_kz bigint not null check(amount_kz in (96,145,489)),
 platform_fee_kz bigint not null,
 creator_amount_kz bigint not null,
 created_at timestamptz not null default now()
);
create table if not exists public.withdrawal_requests (
 id uuid primary key default gen_random_uuid(),
 creator_id uuid not null references public.profiles(id),
 amount_kz bigint not null check(amount_kz >= 1500),
 payout_details jsonb not null,
 status text not null default 'pending' check(status in ('pending','approved','paid','rejected')),
 created_at timestamptz not null default now()
);
create table if not exists public.sponsorship_campaigns (
 id uuid primary key default gen_random_uuid(),
 owner_id uuid not null references public.profiles(id) on delete cascade,
 page_id uuid references public.pages(id) on delete cascade,
 amount_kz bigint not null check(amount_kz >= 1238),
 status text not null default 'pending' check(status in ('pending','active','rejected','ended')),
 starts_at timestamptz,
 ends_at timestamptz,
 created_at timestamptz not null default now()
);

-- Liga RLS. As políticas abaixo dão acesso básico; operações financeiras/admin
-- ficam sem políticas para clientes e devem passar por Edge Functions seguras.
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

-- Perfis: leitura pública limitada pelo que a aplicação expõe; cada utilizador
-- só pode criar/editar o seu próprio perfil. Campos sensíveis exigem função backend.
drop policy if exists "profiles_read" on public.profiles;
create policy "profiles_read" on public.profiles for select using (true);
drop policy if exists "profiles_insert_self" on public.profiles;
create policy "profiles_insert_self" on public.profiles for insert with check (auth.uid() = id);
drop policy if exists "profiles_update_self" on public.profiles;
create policy "profiles_update_self" on public.profiles for update using (auth.uid() = id) with check (auth.uid() = id);

-- Publicações públicas; só o dono cria/edita/apaga.
drop policy if exists "posts_read" on public.posts;
create policy "posts_read" on public.posts for select using (true);
drop policy if exists "posts_insert_self" on public.posts;
create policy "posts_insert_self" on public.posts for insert with check (auth.uid() = user_id);
drop policy if exists "posts_update_owner" on public.posts;
create policy "posts_update_owner" on public.posts for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
drop policy if exists "posts_delete_owner" on public.posts;
create policy "posts_delete_owner" on public.posts for delete using (auth.uid() = user_id);

-- Gostos e comentários.
drop policy if exists "likes_read" on public.post_likes;
create policy "likes_read" on public.post_likes for select using (true);
drop policy if exists "likes_insert_self" on public.post_likes;
create policy "likes_insert_self" on public.post_likes for insert with check (auth.uid() = user_id);
drop policy if exists "likes_delete_self" on public.post_likes;
create policy "likes_delete_self" on public.post_likes for delete using (auth.uid() = user_id);
drop policy if exists "comments_read" on public.comments;
create policy "comments_read" on public.comments for select using (true);
drop policy if exists "comments_insert_self" on public.comments;
create policy "comments_insert_self" on public.comments for insert with check (auth.uid() = user_id);
drop policy if exists "comments_delete_self" on public.comments;
create policy "comments_delete_self" on public.comments for delete using (auth.uid() = user_id);

-- Pedidos de amizade: participantes podem ver; remetente cria; destinatário responde.
drop policy if exists "friend_requests_participants_read" on public.friend_requests;
create policy "friend_requests_participants_read" on public.friend_requests for select using (auth.uid() = sender_id or auth.uid() = receiver_id);
drop policy if exists "friend_requests_sender_insert" on public.friend_requests;
create policy "friend_requests_sender_insert" on public.friend_requests for insert with check (auth.uid() = sender_id);
drop policy if exists "friend_requests_receiver_update" on public.friend_requests;
create policy "friend_requests_receiver_update" on public.friend_requests for update using (auth.uid() = receiver_id) with check (auth.uid() = receiver_id);

-- Seguir, páginas e anúncios.
drop policy if exists "follows_read" on public.follows;
create policy "follows_read" on public.follows for select using (true);
drop policy if exists "follows_insert_self" on public.follows;
create policy "follows_insert_self" on public.follows for insert with check (auth.uid() = follower_id);
drop policy if exists "follows_delete_self" on public.follows;
create policy "follows_delete_self" on public.follows for delete using (auth.uid() = follower_id);
drop policy if exists "pages_read" on public.pages;
create policy "pages_read" on public.pages for select using (true);
drop policy if exists "pages_owner_insert" on public.pages;
create policy "pages_owner_insert" on public.pages for insert with check (auth.uid() = owner_id);
drop policy if exists "pages_owner_update" on public.pages;
create policy "pages_owner_update" on public.pages for update using (auth.uid() = owner_id) with check (auth.uid() = owner_id);
drop policy if exists "market_read" on public.market_listings;
create policy "market_read" on public.market_listings for select using (status = 'active' or auth.uid() = seller_id);
drop policy if exists "market_insert_self" on public.market_listings;
create policy "market_insert_self" on public.market_listings for insert with check (auth.uid() = seller_id);
drop policy if exists "market_update_self" on public.market_listings;
create policy "market_update_self" on public.market_listings for update using (auth.uid() = seller_id) with check (auth.uid() = seller_id);
drop policy if exists "market_delete_self" on public.market_listings;
create policy "market_delete_self" on public.market_listings for delete using (auth.uid() = seller_id);

-- IMPORTANTE: não criar políticas para payment_requests, gifts,
-- withdrawal_requests ou sponsorship_campaigns nesta fase. A escrita/leitura
-- destas tabelas deve ser feita por funções backend com validação e autorização.
-- Também mover gold_verified_until para uma tabela protegida ou impedir alterações
-- desse campo por clientes antes de abrir a aplicação ao público.


-- Stories de fotografia: duração padrão de 24 horas.
create table if not exists public.stories (
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null references public.profiles(id) on delete cascade,
 media_path text not null,
 media_type text not null default 'image' check(media_type = 'image'),
 expires_at timestamptz not null default (now() + interval '24 hours'),
 created_at timestamptz not null default now()
);
alter table public.stories enable row level security;
drop policy if exists "stories_read_active" on public.stories;
create policy "stories_read_active" on public.stories for select using (expires_at > now());
drop policy if exists "stories_insert_self" on public.stories;
create policy "stories_insert_self" on public.stories for insert with check (auth.uid() = user_id);
drop policy if exists "stories_delete_self" on public.stories;
create policy "stories_delete_self" on public.stories for delete using (auth.uid() = user_id);

-- Catálogo musical: só publicar faixas com licenças verificadas.
create table if not exists public.music_catalog (
 id uuid primary key default gen_random_uuid(),
 title text not null,
 artist_name text not null,
 audio_path text not null,
 rights_holder text not null,
 license_reference text not null,
 allowed_territories text[] not null,
 allowed_uses text[] not null,
 license_starts_at timestamptz not null,
 license_ends_at timestamptz,
 review_status text not null default 'pending' check(review_status in ('pending','approved','rejected','expired')),
 created_at timestamptz not null default now()
);
alter table public.music_catalog enable row level security;
drop policy if exists "music_read_approved" on public.music_catalog;
create policy "music_read_approved" on public.music_catalog for select using (
 review_status = 'approved'
 and license_starts_at <= now()
 and (license_ends_at is null or license_ends_at > now())
 and ('ANG' = any(allowed_territories) or '*' = any(allowed_territories))
);
-- Sem escrita pública: aprovação e gestão do catálogo só pelo backend/admin.
