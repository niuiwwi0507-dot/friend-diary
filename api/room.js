```javascript
const crypto = require("node:crypto");

const URL = process.env.SUPABASE_URL;
const KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

function send(res, status, data) {
  return res.status(status).json(data);
}

function hashPassword(password, salt) {
  return crypto
    .pbkdf2Sync(password, salt, 100000, 32, "sha256")
    .toString("hex");
}

function verifyPassword(password, stored) {
  const [salt, expected] = (stored || "").split(":");
  if (!salt || !expected) return false;

  const actual = hashPassword(password, salt);
  const a = Buffer.from(actual, "hex");
  const b = Buffer.from(expected, "hex");

  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function db(path, options = {}) {
  if (!URL || !KEY) {
    throw new Error("Supabase 환경 변수가 설정되지 않았습니다.");
  }

  const response = await fetch(`${URL}/rest/v1/${path}`, {
    ...options,
    headers: {
      apikey: KEY,
      Authorization: `Bearer ${KEY}`,
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  const text = await response.text();

  if (!response.ok) {
    throw new Error(`Supabase 오류 ${response.status}: ${text}`);
  }

  return text ? JSON.parse(text) : null;
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    return send(res, 405, { error: "POST 요청만 가능합니다." });
  }

  try {
    const {
      action,
      roomName,
      password,
      nickname,
      content,
      roomId,
    } = req.body || {};

    if (!URL || !KEY) {
      return send(res, 500, {
        error: "Vercel의 Supabase 환경 변수를 확인해 주세요.",
      });
    }

    if (action === "create") {
      if (!roomName || !password || !nickname) {
        return send(res, 400, {
          error: "방 이름, 비밀번호, 닉네임을 입력해 주세요.",
        });
      }

      const salt = crypto.randomBytes(16).toString("hex");
      const passwordHash = `${salt}:${hashPassword(password, salt)}`;

      const rows = await db("rooms", {
        method: "POST",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify([{
          name: roomName,
          password_hash: passwordHash,
        }]),
      });

      const room = rows && rows[0];

      if (!room) {
        return send(res, 500, { error: "방을 만들지 못했습니다." });
      }

      return send(res, 200, {
        success: true,
        room: { id: room.id, name: room.name },
        nickname,
      });
    }

    if (action === "join") {
      if (!roomName || !password || !nickname) {
        return send(res, 400, {
          error: "방 이름, 비밀번호, 닉네임을 입력해 주세요.",
        });
      }

      const rooms = await db(
        `rooms?name=eq.${encodeURIComponent(roomName)}&select=id,name,password_hash`
      );

      const room = rooms && rooms[0];

      if (!room || !verifyPassword(password, room.password_hash)) {
        return send(res, 401, {
          error: "방 이름 또는 비밀번호가 올바르지 않습니다.",
        });
      }

      return send(res, 200, {
        success: true,
        room: { id: room.id, name: room.name },
        nickname,
      });
    }

    if (action === "write") {
      if (!roomId || !nickname || !content) {
        return send(res, 400, {
          error: "방, 닉네임, 일기 내용을 확인해 주세요.",
        });
      }

      await db("entries", {
        method: "POST",
        body: JSON.stringify([{
          room_id: roomId,
          nickname,
          content,
        }]),
      });

      return send(res, 200, { success: true });
    }

    if (action === "read") {
      if (!roomId) {
        return send(res, 400, { error: "방 정보가 없습니다." });
      }

      const entries = await db(
        `entries?room_id=eq.${encodeURIComponent(roomId)}&select=id,nickname,content,created_at&order=created_at.asc`
      );

      return send(res, 200, { success: true, entries });
    }

    return send(res, 400, { error: "알 수 없는 요청입니다." });
  } catch (error) {
    console.error("room API error:", error);
    return send(res, 500, {
      error: error.message || "서버에서 오류가 발생했습니다.",
    });
  }
};
```
