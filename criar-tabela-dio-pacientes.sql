-- Tabela para pacientes do DIO-V2 (sincronização entre dispositivos)
CREATE TABLE IF NOT EXISTS dio_pacientes (
  id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  nome        TEXT NOT NULL,
  nascimento  TEXT,
  telefone    TEXT,
  obs         TEXT,
  images      TEXT DEFAULT '[]',
  overlays    TEXT DEFAULT '{}',
  drawings    TEXT DEFAULT '{}',
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  deleted_at  TIMESTAMPTZ
);

-- RLS: permitir leitura/escrita para usuários autenticados via service_role
ALTER TABLE dio_pacientes ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Service role full access" ON dio_pacientes USING (true) WITH CHECK (true);
