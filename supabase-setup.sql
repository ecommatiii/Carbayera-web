-- Ejecutar esto en Supabase: Panel del proyecto -> SQL Editor -> New query -> pegar y RUN

create table if not exists reservas (
  id uuid primary key default gen_random_uuid(),
  nombre text not null,
  telefono text not null,
  email text not null,
  comensales integer not null,
  fecha date not null,
  turno text not null,
  motivo text default 'general',
  comentarios text,
  ip text,
  estado text default 'pendiente',
  created_at timestamptz default now()
);

-- Activar Row Level Security: nadie puede leer ni escribir directo desde el
-- navegador. Solo la función backend (con la service role key, que se
-- salta RLS a propósito) puede insertar reservas.
alter table reservas enable row level security;

-- No se crean políticas de acceso público a propósito: sin ninguna
-- política, ni el anon key ni ningún usuario puede leer/escribir esta
-- tabla desde el frontend. Solo tú, entrando a Supabase con tu cuenta,
-- o la función backend con la service role key, pueden acceder.
