'use strict';

const express  = require('express');
const cors     = require('cors');
const helmet   = require('helmet');
const path     = require('path');
const { pool } = require('./db');

const datasetsRouter    = require('./routes/datasets');
const uploadRouter      = require('./routes/upload');
const experimentsRouter = require('./routes/experiments');

const app  = express();
const PORT = process.env.PORT || 4000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '5mb' }));

// Health check (used by Docker healthcheck + nginx upstream)
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', db: 'ok', ts: new Date().toISOString() });
  } catch {
    res.status(503).json({ status: 'error', db: 'unreachable' });
  }
});

// Routes — nginx strips /api prefix before forwarding
app.use('/datasets',    datasetsRouter);
app.use('/upload',      uploadRouter);
app.use('/experiments', experimentsRouter);

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

app.use((err, req, res, _next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: err.message || 'Internal server error' });
});

app.listen(PORT, '0.0.0.0', () =>
  console.log(`Backend listening on :${PORT}`)
);
