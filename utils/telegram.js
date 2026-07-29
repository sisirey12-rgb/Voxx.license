const axios = require("axios");

async function sendTelegram(message) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;

  if (!token || !chatId) {
    console.warn("Telegram is not configured.");
    return;
  }

  try {
    await axios.post(
      `https://api.telegram.org/bot${token}/sendMessage`,
      {
        chat_id: chatId,
        text: message,
        parse_mode: "HTML",
      },
      {
        timeout: 10000,
      }
    );
  } catch (err) {
    console.error(
      "Telegram send failed:",
      err.response?.data || err.message
    );
  }
}

module.exports = { sendTelegram };
