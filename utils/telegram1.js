const axios = require("axios");

class TelegramClient {
    constructor() {
        this.token = process.env.TELEGRAM_BOT_TOKEN;
        this.chatId = process.env.TELEGRAM_CHAT_ID;

        this.api = this.token
            ? `https://api.telegram.org/bot${this.token}`
            : null;
    }

    enabled() {
        return Boolean(
            this.token &&
            this.chatId &&
            this.api
        );
    }

    async send(text, options = {}) {
        if (!this.enabled()) {
            console.warn("[Notify] Telegram disabled.");
            return false;
        }

        try {
            await axios.post(
                `${this.api}/sendMessage`,
                {
                    chat_id: this.chatId,
                    text,
                    parse_mode: "HTML",
                    disable_web_page_preview: true,
                    disable_notification:
                        options.silent ?? false
                },
                {
                    timeout: 10000
                }
            );

            return true;

        } catch (err) {

            console.error(
                "[Notify] Telegram Error:",
                err.response?.data || err.message
            );

            return false;
        }
    }

    async photo(photoUrl, caption = "") {

        if (!this.enabled()) return false;

        try {

            await axios.post(
                `${this.api}/sendPhoto`,
                {
                    chat_id: this.chatId,
                    photo: photoUrl,
                    caption,
                    parse_mode: "HTML"
                }
            );

            return true;

        } catch (err) {

            console.error(
                "[Notify] Telegram Photo Error:",
                err.response?.data || err.message
            );

            return false;
        }

    }

    async document(fileUrl, caption = "") {

        if (!this.enabled()) return false;

        try {

            await axios.post(
                `${this.api}/sendDocument`,
                {
                    chat_id: this.chatId,
                    document: fileUrl,
                    caption,
                    parse_mode: "HTML"
                }
            );

            return true;

        } catch (err) {

            console.error(
                "[Notify] Telegram Document Error:",
                err.response?.data || err.message
            );

            return false;
        }

    }

    async animation(gifUrl, caption = "") {

        if (!this.enabled()) return false;

        try {

            await axios.post(
                `${this.api}/sendAnimation`,
                {
                    chat_id: this.chatId,
                    animation: gifUrl,
                    caption,
                    parse_mode: "HTML"
                }
            );

            return true;

        } catch (err) {

            console.error(
                "[Notify] Telegram Animation Error:",
                err.response?.data || err.message
            );

            return false;
        }

    }

    async test() {

        return this.send(
`🟢 <b>VOXX Notify v3</b>

Telegram connection established successfully.

Time:
${new Date().toLocaleString()}`
        );

    }

}

module.exports = new TelegramClient();
