-- LAURIGRAM v3: fotos de perfil/capa e mensagens privadas
-- Executar DEPOIS de supabase_schema_inicial.sql e supabase_setup_v2.sql.

-- Bucket público apenas para imagens de perfil/capa; os caminhos são sempre por utilizador.
insert into storage.buckets (id,name,public,file_size_limit,allowed_mime_types)
values ('profile-media','profile-media',true,5242880,array['image/jpeg','image/png','image/webp'])
on conflict (id) do update set public=true,file_size_limit=5242880,allowed_mime_types=array['image/jpeg','image/png','image/webp'];

drop policy if exists "profile_media_public_read" on storage.objects;
create policy "profile_media_public_read" on storage.objects for select
using (bucket_id='profile-media');
drop policy if exists "profile_media_owner_insert" on storage.objects;
create policy "profile_media_owner_insert" on storage.objects for insert to authenticated
with check (bucket_id='profile-media' and (storage.foldername(name))[1]=auth.uid()::text);
drop policy if exists "profile_media_owner_update" on storage.objects;
create policy "profile_media_owner_update" on storage.objects for update to authenticated
using (bucket_id='profile-media' and (storage.foldername(name))[1]=auth.uid()::text)
with check (bucket_id='profile-media' and (storage.foldername(name))[1]=auth.uid()::text);
drop policy if exists "profile_media_owner_delete" on storage.objects;
create policy "profile_media_owner_delete" on storage.objects for delete to authenticated
using (bucket_id='profile-media' and (storage.foldername(name))[1]=auth.uid()::text);

create table if not exists public.conversations (
 id uuid primary key default gen_random_uuid(),
 user_one uuid not null references public.profiles(id) on delete cascade,
 user_two uuid not null references public.profiles(id) on delete cascade,
 created_at timestamptz not null default now(),
 constraint conversations_distinct_users check(user_one <> user_two),
 constraint conversations_sorted_users check(user_one < user_two),
 constraint conversations_unique_pair unique(user_one,user_two)
);
create table if not exists public.messages (
 id uuid primary key default gen_random_uuid(),
 conversation_id uuid not null references public.conversations(id) on delete cascade,
 sender_id uuid not null references public.profiles(id) on delete cascade,
 body text not null check(char_length(body) between 1 and 4000),
 created_at timestamptz not null default now()
);
create index if not exists messages_conversation_created_idx on public.messages(conversation_id,created_at);
alter table public.conversations enable row level security;
alter table public.messages enable row level security;
revoke all on public.conversations,public.messages from public,anon,authenticated;
grant select,insert on public.conversations to authenticated;
grant select,insert on public.messages to authenticated;
drop policy if exists "conversation_participant_read" on public.conversations;
create policy "conversation_participant_read" on public.conversations for select to authenticated
using (auth.uid()=user_one or auth.uid()=user_two);
drop policy if exists "conversation_participant_create" on public.conversations;
create policy "conversation_participant_create" on public.conversations for insert to authenticated
with check (auth.uid()=user_one or auth.uid()=user_two);
drop policy if exists "message_participant_read" on public.messages;
create policy "message_participant_read" on public.messages for select to authenticated
using (exists(select 1 from public.conversations c where c.id=conversation_id and (auth.uid()=c.user_one or auth.uid()=c.user_two)));
drop policy if exists "message_sender_insert" on public.messages;
create policy "message_sender_insert" on public.messages for insert to authenticated
with check (auth.uid()=sender_id and exists(select 1 from public.conversations c where c.id=conversation_id and (auth.uid()=c.user_one or auth.uid()=c.user_two)));

-- Actualização dos preços do catálogo de presentes.
alter table public.gifts drop constraint if exists gifts_amount_kz_check;
alter table public.gifts add constraint gifts_amount_kz_check check(amount_kz in (96,145,489));
-- A divisão exacta 70/30 é calculada em Kz inteiros com arredondamento para baixo no criador.
