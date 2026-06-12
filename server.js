require('dotenv').config({ path: require('path').join(__dirname, '.env') });
const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const path     = require('path');
const multer   = require('multer');
const Anthropic = require('@anthropic-ai/sdk');
const { createClient } = require('@supabase/supabase-js');

const upload    = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024, files: 10 } });
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const app  = express();
const PORT = process.env.PORT || 3334;
const JWT_SECRET = process.env.JWT_SECRET || 'oral-unic-dio-secret-2026';

// ── Supabase ─────────────────────────────────────────────────
const supa = createClient(
  process.env.SUPABASE_URL || 'https://ugsolisojqawbjaeencq.supabase.co',
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { persistSession: false } }
);

// ── Middleware ───────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, '..'), {
  etag: false, lastModified: false,
  setHeaders: (res) => { res.setHeader('Cache-Control', 'no-store'); }
}));

// ── Auth middleware ──────────────────────────────────────────
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: 'Token ausente' });
  try {
    req.user = jwt.verify(h.replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido' });
  }
}
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  next();
}
function dentistOrAdmin(req, res, next) {
  if (req.user.role !== 'dentist' && req.user.role !== 'admin')
    return res.status(403).json({ error: 'Apenas dentistas ou admin' });
  next();
}

// ── Helper: erros Supabase ────────────────────────────────────
function dbErr(res, error, msg = 'Erro no banco') {
  console.error(msg, error?.message);
  return res.status(500).json({ error: error?.message || msg });
}

// ══════════════════════════════════════════════════════════════
//  AUTH
// ══════════════════════════════════════════════════════════════
app.get('/api/login-users', async (req, res) => {
  const { data, error } = await supa.from('users').select('username,name').eq('active', true);
  if (error) return dbErr(res, error);
  res.json((data || []).map(u => ({ username: u.username, name: u.name || u.username })));
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Informe usuário e senha' });

  const { data: users } = await supa.from('users').select('*').eq('username', username).limit(1);
  const user = users?.[0];
  if (!user) return res.status(401).json({ error: 'Usuário não encontrado' });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Senha incorreta' });

  const token = jwt.sign(
    { id: user.id, username: user.username, name: user.name, role: user.role },
    JWT_SECRET, { expiresIn: '12h' }
  );
  res.json({ token, user: { id: user.id, username: user.username, name: user.name, role: user.role } });
});

app.get('/api/me', auth, (req, res) => res.json(req.user));

app.get('/api/auto-token', async (req, res) => {
  const { data: users } = await supa.from('users').select('*').eq('role', 'admin').limit(1);
  const user = users?.[0];
  if (!user) return res.status(500).json({ error: 'Admin não encontrado' });
  const token = jwt.sign(
    { id: user.id, username: user.username, name: user.name, role: user.role },
    JWT_SECRET, { expiresIn: '30d' }
  );
  res.json({ token, user: { id: user.id, username: user.username, name: user.name, role: user.role } });
});

// ══════════════════════════════════════════════════════════════
//  USUÁRIOS (admin)
// ══════════════════════════════════════════════════════════════
app.get('/api/users', auth, adminOnly, async (req, res) => {
  const { data, error } = await supa.from('users').select('id,username,name,role,active,created_at');
  if (error) return dbErr(res, error);
  res.json(data || []);
});

app.post('/api/users', auth, adminOnly, async (req, res) => {
  const { username, password, name, role } = req.body;
  if (!username || !password || !name || !role) return res.status(400).json({ error: 'Preencha todos os campos' });
  if (!['admin', 'dentist', 'patient'].includes(role)) return res.status(400).json({ error: 'Perfil inválido' });

  const hash = await bcrypt.hash(password, 10);
  const { data, error } = await supa.from('users').insert({ username, password_hash: hash, name, role }).select('id,username,name,role').single();
  if (error) return dbErr(res, error, 'Usuário já existe ou erro ao criar');
  res.json(data);
});

app.put('/api/users/:id', auth, adminOnly, async (req, res) => {
  const { name, role, password } = req.body;
  const update = { name, role };
  if (password) update.password_hash = await bcrypt.hash(password, 10);
  const { error } = await supa.from('users').update(update).eq('id', req.params.id);
  if (error) return dbErr(res, error);
  res.json({ ok: true });
});

app.delete('/api/users/:id', auth, adminOnly, async (req, res) => {
  const { error } = await supa.from('users').update({ active: false, deleted_at: new Date().toISOString() }).eq('id', req.params.id);
  if (error) return dbErr(res, error);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
//  PACIENTES
// ══════════════════════════════════════════════════════════════
function canAccessPatient(user, patient) {
  if (user.role === 'admin' || user.role === 'dentist') return true;
  if (user.role === 'patient' && patient.linked_user_id === user.id) return true;
  return false;
}

app.get('/api/patients', auth, async (req, res) => {
  let q = supa.from('patients').select('*').is('deleted_at', null);
  if (req.user.role === 'patient') q = q.eq('linked_user_id', req.user.id);
  const { data, error } = await q;
  if (error) return dbErr(res, error);
  res.json(data || []);
});

app.get('/api/patients/:id', auth, async (req, res) => {
  const { data, error } = await supa.from('patients').select('*').eq('id', req.params.id).single();
  if (error || !data) return res.status(404).json({ error: 'Paciente não encontrado' });
  if (!canAccessPatient(req.user, data)) return res.status(403).json({ error: 'Acesso negado' });
  res.json(data);
});

app.post('/api/patients', auth, dentistOrAdmin, async (req, res) => {
  const ficha = (req.body.ficha || '').toString().trim();
  if (ficha) {
    const { data: ex } = await supa.from('patients').select('id,nome').eq('ficha', ficha).is('deleted_at', null).limit(1);
    if (ex?.length) return res.status(409).json({ error: `Ficha #${ficha} já está cadastrada para "${ex[0].nome}".` });
  }
  const { _id, ...body } = req.body;
  const { data, error } = await supa.from('patients').insert({ ...body, ficha: ficha || null }).select('*').single();
  if (error) return dbErr(res, error);
  res.json(data);
});

app.put('/api/patients/:id', auth, dentistOrAdmin, async (req, res) => {
  const { _id, id, ...update } = req.body;
  const novaFicha = (update.ficha || '').toString().trim();
  if (novaFicha) {
    const { data: ex } = await supa.from('patients').select('id,nome').eq('ficha', novaFicha).neq('id', req.params.id).is('deleted_at', null).limit(1);
    if (ex?.length) return res.status(409).json({ error: `Ficha #${novaFicha} já está cadastrada para "${ex[0].nome}".` });
  }
  const { error } = await supa.from('patients').update({ ...update, ficha: novaFicha || null }).eq('id', req.params.id);
  if (error) return dbErr(res, error);
  res.json({ ok: true });
});

app.delete('/api/patients/:id', auth, adminOnly, async (req, res) => {
  await supa.from('patients').update({ deleted_at: new Date().toISOString() }).eq('id', req.params.id);
  await supa.from('planning').update({ deleted_at: new Date().toISOString() }).eq('patient_id', req.params.id);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
//  PLANEJAMENTO
// ══════════════════════════════════════════════════════════════
app.get('/api/patients/:id/planning', auth, async (req, res) => {
  const { data: patient } = await supa.from('patients').select('id,linked_user_id').eq('id', req.params.id).single();
  if (!patient) return res.status(404).json({ error: 'Paciente não encontrado' });
  if (!canAccessPatient(req.user, patient)) return res.status(403).json({ error: 'Acesso negado' });
  const { data, error } = await supa.from('planning').select('*').eq('patient_id', req.params.id).is('deleted_at', null).order('sort_order', { ascending: true });
  if (error) return dbErr(res, error);
  res.json(data || []);
});

app.post('/api/patients/:id/planning', auth, dentistOrAdmin, async (req, res) => {
  const step = {
    patient_id:               req.params.id,
    sort_order:               req.body.order || req.body.sort_order || 1,
    tipo:                     req.body.tipo || '',
    descricao_tipo:           req.body.descricaoTipo || req.body.descricao_tipo || '',
    tooth:                    req.body.tooth || '',
    procedure:                req.body.procedure || '',
    duration:                 req.body.duration || '',
    tempo_dentista:           req.body.tempoDentista || req.body.tempo_dentista || '',
    dentista:                 req.body.dentista || '',
    notes:                    req.body.notes || '',
    retorno_em:               req.body.retornoEm || req.body.retorno_em || '',
    descricao_proc:           req.body.descricaoProc || req.body.descricao_proc || '',
    status:                   req.body.status || 'pending',
    requer_termo_protetica:   !!req.body.requerTermoProtetica,
    requer_termo_finalizacao: !!req.body.requerTermoFinalizacao,
    sem_comanda:              !!req.body.semComanda,
    created_by:               null,
    created_by_name:          req.user.name,
    signatures:               [],
    historico:                [],
  };
  const { data, error } = await supa.from('planning').insert(step).select('*').single();
  if (error) return dbErr(res, error);
  res.json(data);
});

app.put('/api/patients/:id/planning/:stepId', auth, dentistOrAdmin, async (req, res) => {
  const { _id, id, patientId, patient_id, signatures, ...update } = req.body;
  // Mapeia camelCase → snake_case
  if (update.descricaoTipo !== undefined)   { update.descricao_tipo = update.descricaoTipo; delete update.descricaoTipo; }
  if (update.tempoDentista !== undefined)   { update.tempo_dentista = update.tempoDentista; delete update.tempoDentista; }
  if (update.retornoEm !== undefined)       { update.retorno_em = update.retornoEm; delete update.retornoEm; }
  if (update.descricaoProc !== undefined)   { update.descricao_proc = update.descricaoProc; delete update.descricaoProc; }
  if (update.requerTermoProtetica !== undefined) { update.requer_termo_protetica = update.requerTermoProtetica; delete update.requerTermoProtetica; }
  if (update.requerTermoFinalizacao !== undefined) { update.requer_termo_finalizacao = update.requerTermoFinalizacao; delete update.requerTermoFinalizacao; }
  if (update.semComanda !== undefined)      { update.sem_comanda = update.semComanda; delete update.semComanda; }
  if (update.termoProtetica !== undefined)  { update.termo_protetica = update.termoProtetica; delete update.termoProtetica; }
  if (update.order !== undefined)           { update.sort_order = update.order; delete update.order; }

  // Se mudou status, registra no histórico
  if (update.status) {
    const { data: step } = await supa.from('planning').select('status,historico').eq('id', req.params.stepId).single();
    if (step && step.status !== update.status) {
      const entrada = { status: update.status, statusAnterior: step.status, por: req.user.name, em: new Date().toISOString() };
      update.historico = [...(step.historico || []), entrada];
    }
  }

  const { error } = await supa.from('planning').update(update).eq('id', req.params.stepId).eq('patient_id', req.params.id);
  if (error) return dbErr(res, error);
  res.json({ ok: true });
});

app.delete('/api/patients/:id/planning/:stepId', auth, dentistOrAdmin, async (req, res) => {
  await supa.from('planning').update({ deleted_at: new Date().toISOString() }).eq('id', req.params.stepId).eq('patient_id', req.params.id);
  res.json({ ok: true });
});

// ── Assinatura ───────────────────────────────────────────────
app.post('/api/patients/:id/planning/:stepId/sign', auth, async (req, res) => {
  const { signatureData, signatureType } = req.body;
  if (!signatureData) return res.status(400).json({ error: 'Dados de assinatura ausentes' });
  if (req.user.role === 'patient' && signatureType !== 'patient') return res.status(403).json({ error: 'Paciente só pode assinar como paciente' });

  const { data: step } = await supa.from('planning').select('*').eq('id', req.params.stepId).eq('patient_id', req.params.id).single();
  if (!step) return res.status(404).json({ error: 'Etapa não encontrada' });

  let signerName = req.user.name;
  if (signatureType === 'patient' && req.user.role !== 'patient') {
    signerName = req.body.patientName || signerName;
  }

  const sig = { type: signatureType, signerName, signerRole: req.user.role, signatureData, signedAt: new Date().toISOString() };
  const sigs = (step.signatures || []).filter(s => s.type !== signatureType);
  sigs.push(sig);

  const newStatus = sigs.some(s => s.type === 'dentist') && sigs.some(s => s.type === 'patient')
    ? 'signed' : sigs.some(s => s.type === 'dentist') ? 'dentist_signed' : 'patient_signed';

  const { error } = await supa.from('planning').update({ signatures: sigs, status: newStatus }).eq('id', req.params.stepId);
  if (error) return dbErr(res, error);
  res.json({ ok: true, signatures: sigs, status: newStatus });
});

// ══════════════════════════════════════════════════════════════
//  IMAGENS DO PACIENTE
// ══════════════════════════════════════════════════════════════
app.put('/api/patients/:id/images', auth, dentistOrAdmin, async (req, res) => {
  const { error } = await supa.from('patients').update({ images: req.body.images }).eq('id', req.params.id);
  if (error) return dbErr(res, error);
  res.json({ ok: true });
});

app.put('/api/patients/:id/overlays', auth, dentistOrAdmin, async (req, res) => {
  const { error } = await supa.from('patients').update({ overlays: req.body.overlays, drawings: req.body.drawings }).eq('id', req.params.id);
  if (error) return dbErr(res, error);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
//  CONSULTAS
// ══════════════════════════════════════════════════════════════
app.get('/api/patients/:id/consultas', auth, async (req, res) => {
  const { data: patient } = await supa.from('patients').select('id,linked_user_id').eq('id', req.params.id).single();
  if (!patient) return res.status(404).json({ error: 'Paciente não encontrado' });
  if (!canAccessPatient(req.user, patient)) return res.status(403).json({ error: 'Acesso negado' });
  const { data, error } = await supa.from('consultas').select('*').eq('patient_id', req.params.id).is('deleted_at', null).order('data', { ascending: true });
  if (error) return dbErr(res, error);
  res.json(data || []);
});

app.post('/api/patients/:id/consultas', auth, dentistOrAdmin, async (req, res) => {
  const { data, falta, faltaObs, extra, extraObs, registradoPor } = req.body;
  const { data: doc, error } = await supa.from('consultas').insert({
    patient_id:          req.params.id,
    data:                data || new Date().toISOString().slice(0,10),
    falta:               !!falta,
    falta_obs:           faltaObs || '',
    extra:               !!extra,
    extra_obs:           extraObs || '',
    registrado_por_nome: registradoPor || req.user.name,
  }).select('*').single();
  if (error) return dbErr(res, error);
  res.json(doc);
});

// ══════════════════════════════════════════════════════════════
//  ALERTAS GLOBAIS
// ══════════════════════════════════════════════════════════════
app.get('/api/alertas', auth, dentistOrAdmin, async (req, res) => {
  const alertas = [];

  const { data: comandas } = await supa.from('comandas').select('*').is('deleted_at', null);
  (comandas || []).filter(c => {
    const s = c.status || (c.lida ? 'agendado' : 'nova');
    return s === 'nova' || s === 'pendente';
  }).forEach(c => alertas.push({
    tipo: 'comanda_pendente', icon: '📋', cor: '#7c3aed',
    titulo: 'Comanda pendente',
    descricao: `${c.patient_name || 'Paciente'} — ${c.procedimento_concluido || 'sem procedimento'}`,
    patientId: c.patient_id, patientName: c.patient_name,
    em: c.criada_em || c.created_at,
  }));

  const { data: steps } = await supa.from('planning').select('*').eq('status', 'concluido').is('deleted_at', null);
  (steps || []).forEach(s => {
    if (s.requer_termo_protetica && !s.termo_protetica?.assinaturaPaciente) {
      alertas.push({
        tipo: 'termo_pendente', icon: '📝', cor: '#d97706',
        titulo: 'Termo Protético pendente',
        descricao: `Etapa: ${s.procedure || '—'}`,
        patientId: s.patient_id, em: s.updated_at || s.created_at,
      });
    }
  });

  // Enriquece nomes — 1 query IN em vez de N+1
  const patientIds = [...new Set(alertas.filter(a => a.patientId && !a.patientName).map(a => a.patientId))];
  if (patientIds.length) {
    const { data: pats } = await supa.from('patients').select('id,nome').in('id', patientIds);
    const map = Object.fromEntries((pats || []).map(p => [p.id, p.nome]));
    alertas.filter(a => !a.patientName && a.patientId).forEach(a => { a.patientName = map[a.patientId]; });
  }

  alertas.sort((a,b) => new Date(b.em||0) - new Date(a.em||0));
  res.json(alertas);
});

// ══════════════════════════════════════════════════════════════
//  DASHBOARD
// ══════════════════════════════════════════════════════════════
app.get('/api/dashboard/planning', auth, dentistOrAdmin, async (req, res) => {
  const { data, error } = await supa.from('planning').select('*').is('deleted_at', null);
  if (error) return dbErr(res, error);
  res.json(data || []);
});

app.get('/api/dashboard/consultas', auth, dentistOrAdmin, async (req, res) => {
  const { data, error } = await supa.from('consultas').select('*').is('deleted_at', null);
  if (error) return dbErr(res, error);
  res.json(data || []);
});

app.get('/api/agenda/dentistas-ativos-hoje', auth, async (req, res) => {
  const hoje = new Date(); hoje.setHours(0,0,0,0);
  const amanha = new Date(hoje); amanha.setDate(amanha.getDate() + 1);
  const { data } = await supa.from('planning').select('dentista').eq('status', 'concluido')
    .gte('updated_at', hoje.toISOString()).lt('updated_at', amanha.toISOString()).is('deleted_at', null);
  const dentistas = [...new Set((data || []).map(s => (s.dentista || '').trim()).filter(Boolean))];
  res.json({ dentistas });
});

// ══════════════════════════════════════════════════════════════
//  COMANDAS
// ══════════════════════════════════════════════════════════════
app.get('/api/comandas', auth, async (req, res) => {
  const { data, error } = await supa.from('comandas').select('*').is('deleted_at', null).order('created_at', { ascending: false });
  if (error) return dbErr(res, error);
  res.json(data || []);
});

app.post('/api/comandas', auth, async (req, res) => {
  const { patientId, patientName, ficha, stepId, procedimentoConcluido, proximoProcedimento, tempo, retorno, dentista, manutencaoCount, tipoComanda, observacao } = req.body;
  const { data, error } = await supa.from('comandas').insert({
    patient_id:             patientId,
    patient_name:           patientName,
    ficha:                  ficha ? String(ficha) : null,
    step_id:                stepId || null,
    procedimento_concluido: procedimentoConcluido || '',
    proximo_procedimento:   proximoProcedimento || '',
    tempo:                  tempo || '',
    retorno:                retorno || '',
    manutencao_count:       manutencaoCount || 0,
    tipo_comanda:           tipoComanda || 'verde',
    observacao:             observacao || '',
    dentista:               dentista || req.user.name,
    assinatura:             req.user.username,
    assinatura_nome:        req.user.name,
    criada_em:              new Date().toISOString(),
    lida:                   false,
    status:                 'nova',
  }).select('*').single();
  if (error) return dbErr(res, error);
  res.json(data);
});

app.put('/api/comandas/:id/lida', auth, async (req, res) => {
  const novoStatus = req.body.status || 'agendado';
  const { error } = await supa.from('comandas').update({
    status:                novoStatus,
    status_atualizado_em:  new Date().toISOString(),
    lida:                  novoStatus === 'agendado',
  }).eq('id', req.params.id);
  if (error) return dbErr(res, error);
  res.json({ ok: true });
});

app.put('/api/comandas/:id', auth, async (req, res) => {
  const allowed = ['retorno','tempo','proximo_procedimento','proximoProcedimento','status','observacao','tipo_comanda','tipoComanda'];
  const update = {};
  for (const k of allowed) {
    if (req.body[k] !== undefined) {
      const mapped = k === 'proximoProcedimento' ? 'proximo_procedimento' : k === 'tipoComanda' ? 'tipo_comanda' : k;
      update[mapped] = req.body[k];
    }
  }
  const { error } = await supa.from('comandas').update(update).eq('id', req.params.id);
  if (error) return dbErr(res, error);
  res.json({ ok: true });
});

app.delete('/api/comandas/:id', auth, adminOnly, async (req, res) => {
  await supa.from('comandas').update({ deleted_at: new Date().toISOString() }).eq('id', req.params.id);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
//  ADICIONAIS
// ══════════════════════════════════════════════════════════════
app.get('/api/adicionais/:patientId', auth, async (req, res) => {
  const { data, error } = await supa.from('adicionais').select('*').eq('patient_id', req.params.patientId).is('deleted_at', null).order('criado_em', { ascending: false });
  if (error) return dbErr(res, error);
  res.json(data || []);
});

app.post('/api/adicionais', auth, dentistOrAdmin, async (req, res) => {
  const { data, error } = await supa.from('adicionais').insert({
    patient_id:      req.body.patientId,
    patient_name:    req.body.patientName,
    ficha:           req.body.ficha ? String(req.body.ficha) : null,
    descricao:       req.body.descricao || '—',
    justificativa:   req.body.justificativa || '',
    criado_por_nome: req.user.name,
    criado_em:       new Date().toISOString(),
  }).select('*').single();
  if (error) return dbErr(res, error);
  res.json(data);
});

app.delete('/api/adicionais/:id', auth, adminOnly, async (req, res) => {
  await supa.from('adicionais').update({ deleted_at: new Date().toISOString() }).eq('id', req.params.id);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
//  RELACIONAMENTO
// ══════════════════════════════════════════════════════════════
app.get('/api/relacionamento', auth, async (req, res) => {
  const { data, error } = await supa.from('relacionamento').select('*').is('deleted_at', null).order('criado_em', { ascending: false });
  if (error) return dbErr(res, error);
  res.json(data || []);
});

app.post('/api/relacionamento', auth, dentistOrAdmin, async (req, res) => {
  const { data, error } = await supa.from('relacionamento').insert({
    patient_id:     req.body.patientId || '',
    patient_name:   req.body.patientName || '',
    ficha:          req.body.ficha ? String(req.body.ficha) : null,
    tipo:           req.body.tipo || 'ligacao',
    anotacao:       req.body.anotacao || '',
    data_contato:   req.body.dataContato ? new Date(req.body.dataContato).toISOString().slice(0,10) : new Date().toISOString().slice(0,10),
    origem:         req.body.origem || '',
    urgencia:       !!req.body.urgencia,
    realizado:      !!req.body.realizado,
    criado_por_nome: req.user.name,
    criado_em:      new Date().toISOString(),
  }).select('*').single();
  if (error) return dbErr(res, error);
  res.json(data);
});

app.put('/api/relacionamento/:id/flag', auth, dentistOrAdmin, async (req, res) => {
  const flag = req.body.flag;
  if (!['falta','remedio'].includes(flag)) return res.status(400).json({ error: 'flag inválida' });
  const field = flag === 'falta' ? 'flag_falta' : 'flag_remedio';
  const { data: doc } = await supa.from('relacionamento').select(field).eq('id', req.params.id).single();
  if (!doc) return res.status(404).json({ error: 'não encontrado' });
  await supa.from('relacionamento').update({ [field]: !doc[field] }).eq('id', req.params.id);
  res.json({ ok: true });
});

app.put('/api/relacionamento/:id/efetivar', auth, dentistOrAdmin, async (req, res) => {
  const { error } = await supa.from('relacionamento').update({
    efetivado: true, efetivado_em: new Date().toISOString(), efetivado_por_nome: req.user.name
  }).eq('id', req.params.id);
  if (error) return dbErr(res, error);
  res.json({ ok: true });
});

app.delete('/api/relacionamento/:id', auth, adminOnly, async (req, res) => {
  await supa.from('relacionamento').update({ deleted_at: new Date().toISOString() }).eq('id', req.params.id);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
//  RECEITUÁRIOS
// ══════════════════════════════════════════════════════════════
app.get('/api/receituarios', auth, dentistOrAdmin, async (req, res) => {
  const { data, error } = await supa.from('receituarios').select('*').is('deleted_at', null).order('criado_em', { ascending: false });
  if (error) return dbErr(res, error);
  res.json(data || []);
});

app.post('/api/receituarios', auth, dentistOrAdmin, async (req, res) => {
  const { data, error } = await supa.from('receituarios').insert({
    patient_id:      req.body.patientId || '',
    patient_name:    req.body.patientName || '',
    ficha:           req.body.ficha ? String(req.body.ficha) : null,
    step_id:         req.body.stepId || null,
    dentista:        req.body.dentista || req.user.name,
    data:            req.body.data || new Date().toISOString().slice(0,10),
    medicamentos:    req.body.medicamentos || [],
    orientacoes:     req.body.orientacoes || '',
    impresso:        false,
    criado_por_nome: req.user.name,
    criado_em:       new Date().toISOString(),
  }).select('*').single();
  if (error) return dbErr(res, error);
  res.json(data);
});

app.put('/api/receituarios/:id/impresso', auth, dentistOrAdmin, async (req, res) => {
  const { error } = await supa.from('receituarios').update({
    impresso: true, impresso_em: new Date().toISOString(), impresso_por_nome: req.user.name
  }).eq('id', req.params.id);
  if (error) return dbErr(res, error);
  res.json({ ok: true });
});

app.delete('/api/receituarios/:id', auth, adminOnly, async (req, res) => {
  await supa.from('receituarios').update({ deleted_at: new Date().toISOString() }).eq('id', req.params.id);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════
//  OCR — Planejamento
// ══════════════════════════════════════════════════════════════
app.post('/api/ocr-planejamento', auth, upload.array('files', 10), async (req, res) => {
  if (!req.files?.length) return res.status(400).json({ error: 'Nenhum arquivo enviado' });
  if (!process.env.ANTHROPIC_API_KEY) return res.status(500).json({ error: 'ANTHROPIC_API_KEY não configurada' });

  const prompt = `Você é um assistente odontológico especializado em leitura de fichas de planejamento odontológico da clínica Oral Unic.

A tabela tem EXATAMENTE estas colunas nesta ordem:
1. DENTISTA — nome do dentista responsável por aquela etapa (ex: "DR NARTON", "DR AURÉLIO", "CLINICO", "DR SCHARLES")
2. PROCEDIMENTO — nome da consulta/etapa em maiúsculas
3. TEMPO DE CONSULTA — duração (ex: "30 MIN", "2:30 MIN", "45 MIN")
4. RETORNO — prazo de retorno após a consulta (ex: "7 DIAS", "3 MESES", "FINAL DE JANEIRO", "LAB")
5. CONCLUÍDO — marcação de conclusão (ignore)

Fora da tabela, a ficha pode conter:
- Campos FICHA (número do paciente), PACIENTE (nome), OBSERVAÇÃO PESSOAL, OBSERVAÇÃO DO CASO
- Assinaturas ou carimbos de dentistas identificados como "Avaliador" ou "Planejador"

Retorne SOMENTE um JSON válido, sem texto adicional:
{"dentistaAvaliador":null,"dentistaPlanejador":null,"observacaoCaso":null,"etapas":[{"procedure":"","duration":"","retorno":"","dentista":"","notes":""}]}

Regras CRÍTICAS:
- A PRIMEIRA coluna é SEMPRE o DENTISTA.
- A coluna RETORNO é a 4ª coluna.
- Cada LINHA DA TABELA = 1 etapa.
- NÃO inclua cabeçalhos como etapas.
- Se a célula DENTISTA de uma linha estiver vazia, use o dentista da linha anterior.
- Retorne APENAS o JSON.`;

  try {
    const allEtapas = [];
    let dentistaAvaliador = null, dentistaPlanejador = null, observacaoCaso = null;
    for (const file of req.files) {
      const response = await anthropic.messages.create({
        model: 'claude-haiku-4-5-20251001', max_tokens: 2048,
        messages: [{ role: 'user', content: [
          { type: 'image', source: { type: 'base64', media_type: file.mimetype, data: file.buffer.toString('base64') } },
          { type: 'text', text: prompt },
        ]}],
      });
      const match = response.content[0].text.match(/\{[\s\S]*\}/);
      if (match) {
        try {
          const parsed = JSON.parse(match[0]);
          if (Array.isArray(parsed.etapas)) allEtapas.push(...parsed.etapas);
          if (parsed.dentistaAvaliador && !dentistaAvaliador) dentistaAvaliador = parsed.dentistaAvaliador;
          if (parsed.dentistaPlanejador && !dentistaPlanejador) dentistaPlanejador = parsed.dentistaPlanejador;
          if (parsed.observacaoCaso && !observacaoCaso) observacaoCaso = parsed.observacaoCaso;
        } catch {}
      }
    }
    const seen = new Set();
    const unique = allEtapas.filter(e => {
      const key = (e.procedure || '').toLowerCase().trim();
      if (seen.has(key)) return false; seen.add(key); return true;
    });
    res.json({ etapas: unique, dentistaAvaliador, dentistaPlanejador, observacaoCaso });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════
//  OCR — Paciente
// ══════════════════════════════════════════════════════════════
app.post('/api/ocr-paciente', auth, (req, res, next) => {
  upload.single('file')(req, res, (err) => {
    if (err) return res.status(400).json({ error: 'Arquivo inválido: ' + err.message });
    next();
  });
}, async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Nenhum arquivo enviado' });
  const prompt = `Analise a imagem de um documento ou ficha de paciente e extraia os campos em JSON:
{"ficha":null,"nome":null,"nascimento":null,"cpf":null,"celular":null,"rua":null,"numero":null,"bairro":null,"cidade":null,"complemento":null}
- nascimento: formato YYYY-MM-DD
- cpf: formato 000.000.000-00
- ficha: apenas números
- Retorne APENAS o JSON.`;

  try {
    const response = await anthropic.messages.create({
      model: 'claude-haiku-4-5-20251001', max_tokens: 512,
      messages: [{ role: 'user', content: [
        { type: 'image', source: { type: 'base64', media_type: req.file.mimetype, data: req.file.buffer.toString('base64') } },
        { type: 'text', text: prompt },
      ]}],
    });
    const match = response.content[0].text.match(/\{[\s\S]*\}/);
    res.json(match ? JSON.parse(match[0]) : {});
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════
//  OCR — Anamnese
// ══════════════════════════════════════════════════════════════
app.post('/api/ocr-anamnese', auth, (req, res, next) => {
  upload.array('files', 10)(req, res, (err) => {
    if (err) return res.status(400).json({ error: 'Arquivo inválido: ' + err.message });
    next();
  });
}, async (req, res) => {
  if (!req.files?.length) return res.status(400).json({ error: 'Nenhum arquivo enviado' });

  const prompt = `Analise a ficha de anamnese odontológica e retorne JSON com as respostas.
Use "sim"/"nao" para perguntas S/N, null se não visível.
Campos: q1-q44 (sim/nao), q2_obs,q3_obs,q6_obs,q7_obs,q8_obs,q9_obs,q12_obs,q13_obs,q14_obs,q15_obs,q38_obs,q39_obs,q40_obs,q42_obs,q43_obs,q44_obs (texto),
respNome (nome assinante), cpf (000.000.000-00), assData (YYYY-MM-DD).
Retorne APENAS o JSON, omita campos null.`;

  try {
    const content = req.files.map(f => ({
      type: 'image', source: { type: 'base64', media_type: f.mimetype.startsWith('image/') ? f.mimetype : 'image/jpeg', data: f.buffer.toString('base64') }
    }));
    content.push({ type: 'text', text: prompt });
    const response = await anthropic.messages.create({
      model: 'claude-haiku-4-5-20251001', max_tokens: 2048,
      messages: [{ role: 'user', content }],
    });
    const match = response.content[0].text.match(/\{[\s\S]*\}/);
    res.json(match ? JSON.parse(match[0]) : {});
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Proxy Kanban ─────────────────────────────────────────────
const https = require('https');
app.get('/kanban-proxy', auth, (req, res) => {
  const target = 'https://iaoraluniccb.github.io/kanban-oral-unic/';
  https.get(target, { headers: { 'User-Agent': 'Mozilla/5.0' } }, (upstream) => {
    res.setHeader('Content-Type', upstream.headers['content-type'] || 'text/html; charset=utf-8');
    res.removeHeader('X-Frame-Options');
    res.removeHeader('Content-Security-Policy');
    upstream.pipe(res);
  }).on('error', () => res.status(502).send('Erro ao carregar Kanban'));
});

// ── Start ────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🦷 Athena — Prontuário Digital | Oral Unic CB`);
  console.log(`   Porta: ${PORT}`);
  console.log(`   Supabase: ${process.env.SUPABASE_URL || 'ugsolisojqawbjaeencq'}\n`);
});
