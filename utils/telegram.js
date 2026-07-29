const axios = require("axios");

async function sendTelegram(message) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;

  if (!token || !chatId) return;

  await axios.post(
    `https://api.telegram.org/bot${token}/sendMessage`,
    {
      chat_id: chatId,
      text: message,
    }
  );
}

module.exports = { sendTelegram };
