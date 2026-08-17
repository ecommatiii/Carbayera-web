// netlify/functions/reservar.js
//
// Backend seguro para el formulario de reservas de La Carbayera.
// - Claves solo en variables de entorno (nunca en el código del frontend)
// - CORS restringido al dominio del sitio
// - Validación y sanitización de todos los campos en el servidor
// - Rate limiting básico contra abuso (por IP y por email)
// - Inserta en Supabase, protegido con Row Level Security

const { createClient } = require("@supabase/supabase-js");

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ALLOWED_ORIGIN =
  process.env.ALLOWED_ORIGIN || "https://lacarbayera-web.netlify.app";

const RATE_LIMIT_WINDOW_MIN = 10; // ventana de tiempo
const RATE_LIMIT_MAX_PER_IP = 5; // máx. intentos por IP en la ventana
const RATE_LIMIT_MAX_PER_EMAIL = 3; // máx. intentos por email en la ventana

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json",
  };
}

function json(statusCode, body) {
  return { statusCode, headers: corsHeaders(), body: JSON.stringify(body) };
}

// Sanitiza texto libre: quita etiquetas HTML/scripts y recorta longitud.
function sanitizeText(value, maxLen) {
  if (typeof value !== "string") return "";
  return value
    .replace(/<[^>]*>/g, "") // quita tags HTML
    .replace(/[<>]/g, "") // quita ángulos sueltos
    .trim()
    .slice(0, maxLen);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 120;
}

function isValidPhone(phone) {
  return /^[\d\s()+-]{6,20}$/.test(phone);
}

function isValidDate(dateStr) {
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return false;
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  return d >= today;
}

exports.handler = async (event) => {
  // Preflight CORS
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: corsHeaders(), body: "" };
  }

  if (event.httpMethod !== "POST") {
    return json(405, { error: "Método no permitido" });
  }

  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    console.error("Faltan variables de entorno de Supabase");
    return json(500, { error: "Error de configuración del servidor" });
  }

  let data;
  try {
    data = JSON.parse(event.body || "{}");
  } catch (e) {
    return json(400, { error: "JSON inválido" });
  }

  // Honeypot anti-bot: si el campo oculto viene relleno, se descarta silenciosamente.
  if (data.empresa_web) {
    return json(200, { ok: true });
  }

  // --- Sanitización y validación en servidor (nunca confiar solo en el frontend) ---
  const nombre = sanitizeText(data.nombre, 80);
  const telefono = sanitizeText(data.telefono, 20);
  const email = sanitizeText(data.email, 120).toLowerCase();
  const comensales = parseInt(data.comensales, 10);
  const fecha = sanitizeText(data.fecha, 10);
  const turno = ["comida", "cena"].includes(data.turno) ? data.turno : null;
  const motivo = ["general", "boda", "comunion", "grupo"].includes(data.motivo)
    ? data.motivo
    : "general";
  const comentarios = sanitizeText(data.comentarios, 500);

  const errors = [];
  if (!nombre || nombre.length < 2) errors.push("nombre");
  if (!isValidPhone(telefono)) errors.push("telefono");
  if (!isValidEmail(email)) errors.push("email");
  if (!Number.isInteger(comensales) || comensales < 1 || comensales > 60)
    errors.push("comensales");
  if (!isValidDate(fecha)) errors.push("fecha");
  if (!turno) errors.push("turno");

  if (errors.length > 0) {
    return json(400, { error: "Datos inválidos: " + errors.join(", ") });
  }

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
  const ip =
    event.headers["x-nf-client-connection-ip"] ||
    event.headers["client-ip"] ||
    "unknown";
  const windowStart = new Date(
    Date.now() - RATE_LIMIT_WINDOW_MIN * 60 * 1000
  ).toISOString();

  // --- Rate limiting: por IP y por email en la ventana de tiempo ---
  const { count: countByIp, error: ipErr } = await supabase
    .from("reservas")
    .select("id", { count: "exact", head: true })
    .eq("ip", ip)
    .gte("created_at", windowStart);

  if (!ipErr && countByIp !== null && countByIp >= RATE_LIMIT_MAX_PER_IP) {
    return json(429, {
      error: "Demasiadas solicitudes desde esta conexión. Probá más tarde.",
    });
  }

  const { count: countByEmail, error: emailErr } = await supabase
    .from("reservas")
    .select("id", { count: "exact", head: true })
    .eq("email", email)
    .gte("created_at", windowStart);

  if (
    !emailErr &&
    countByEmail !== null &&
    countByEmail >= RATE_LIMIT_MAX_PER_EMAIL
  ) {
    return json(429, {
      error: "Ya recibimos varias solicitudes tuyas. Te contactaremos pronto.",
    });
  }

  // --- Inserción en Supabase (protegida con Row Level Security en la tabla) ---
  const { error: insertError } = await supabase.from("reservas").insert([
    {
      nombre,
      telefono,
      email,
      comensales,
      fecha,
      turno,
      motivo,
      comentarios,
      ip,
      estado: "pendiente",
    },
  ]);

  if (insertError) {
    console.error("Error insertando reserva:", insertError.message);
    return json(500, {
      error: "No se pudo guardar la reserva. Probá de nuevo.",
    });
  }

  return json(200, { ok: true });
};
