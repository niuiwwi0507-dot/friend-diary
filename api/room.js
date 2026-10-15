
import crypto from "node:crypto";

const URL = process.env.SUPABASE_URL;
const KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

function send(res, status, data) {
  return res.status(status).json(data);
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, "sha256")
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
  const response = await fetch(`${URL}/rest/v1/${path}`, {
    ...options,
    headers: {
      apikey: KEY,
      Authorization: `Bearer ${KEY}`,
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  const text = await response.text();
  let data = null;

  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }

  if (!response.ok) {
    throw new Error("Database request failed");
  }

  return data;
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return send(res, 405, { error: "POST 요청만 가능합니다." });
  }

  if (!URL || !KEY) {
    return send(res, 500, { error: "서버 환경 변수를 확인해 주세요." });
  }

  try {
    const {
      action, roomName, password, nickname, content
    } = req.body || {};

    if (
      typeof roomName !== "string" ||
      typeof password !== "string" ||
      !roomName.trim() ||
      password.length < 6 ||
      roomName.length > 60
    ) {
      return send(res, 400, {
        error: "방 이름을 입력하고 비밀번호는 6자 이상으로 설정해 주세요."
      });
    }

    const roomFilter =
      `room_name=eq.${encodeURIComponent(roomName.trim())}`;

    if (action === "create") {
      const salt = crypto.randomBytes(16).toString("hex");
      const passwordHash = salt + ":" + hashPassword(password, salt);

      const rooms = await db("rooms", {
        method: "POST",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify([{
          room_name: roomName.trim(),
          password_hash: passwordHash
        }])
      });

      return send(res, 200, {
        success: true,
        roomName: rooms[0].room_name
      });
    }

    const rooms = await db(
      `rooms?${roomFilter}&select=id,room_name,password_hash`
    );

    const room = rooms?.[0];

    if (!room || !verifyPassword(password, room.password_hash)) {
      return send(res, 401, {
        error: "방 이름 또는 비밀번호가 올바르지 않습니다."
      });
    }

    if (action === "join") {
      return send(res, 200, {
        success: true,
        roomName: room.room_name
      });
    }

    if (action === "read") {
      const entries = await db(
        `entries?room_id=eq.${room.id}&select=id,nickname,content,created_at&order=created_at.asc`
      );

      return send(res, 200, { success: true, entries });
    }

    if (action === "write") {
      if (
        typeof nickname !== "string" ||
        !nickname.trim() ||
        nickname.length > 40 ||
        typeof content !== "string" ||
        !content.trim() ||
        content.length > 5000
      ) {
        return send(res, 400, {
          error: "닉네임과 일기 내용을 확인해 주세요."
        });
      }

      await db("entries", {
        method: "POST",
        body: JSON.stringify([{
          room_id: room.id,
          nickname: nickname.trim(),
          content: content.trim()
        }])
      });

      return send(res, 200, { success: true });
    }

    return send(res, 400, { error: "알 수 없는 요청입니다." });
  } catch (error) {
    console.error(error);
    return send(res, 500, {
      error: "요청을 처리하지 못했어요. 설정과 데이터베이스를 확인해 주세요."
    });
  }
}
