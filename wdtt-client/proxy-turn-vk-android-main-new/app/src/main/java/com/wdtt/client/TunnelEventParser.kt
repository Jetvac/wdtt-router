package com.wdtt.client

import org.json.JSONObject

object TunnelEventParser {

    private const val PREFIX = "__WDTT_EVENT__|"

    sealed class Event {
        data class Started(val message: String = "") : Event()
        data class Stopped(val message: String = "") : Event()
        data class Ready(val message: String = "") : Event()
        data class Config(val config: String) : Event()
        data class Stats(
            val active: Int,
            val bytesUp: Long,
            val bytesDown: Long
        ) : Event()

        data class Error(
            val code: String,
            val message: String,
            val fatal: Boolean
        ) : Event()

        data class CaptchaRequest(
            val mode: String,
            val redirectUri: String,
            val sessionToken: String
        ) : Event()

        data class CaptchaDone(
            val success: Boolean,
            val error: String?
        ) : Event()
    }

    

    fun parse(line: String): Event? {
        if (!line.startsWith(PREFIX)) return null
        val withoutPrefix = line.substring(PREFIX.length)
        val typeEnd = withoutPrefix.indexOf('|')
        if (typeEnd == -1) return null

        val type = withoutPrefix.substring(0, typeEnd)
        val payload = try {
            JSONObject(withoutPrefix.substring(typeEnd + 1))
        } catch (_: Exception) {
            JSONObject()
        }

        return when (type) {
            "STARTED" -> Event.Started(payload.optString("message", ""))
            "STOPPED" -> Event.Stopped(payload.optString("message", ""))
            "READY" -> Event.Ready(payload.optString("message", ""))
            "CONFIG" -> Event.Config(payload.optString("config", ""))
            "STATS" -> Event.Stats(
                active = payload.optInt("active", 0),
                bytesUp = payload.optLong("bytes_up", 0L),
                bytesDown = payload.optLong("bytes_down", 0L)
            )
            "ERROR" -> Event.Error(
                code = payload.optString("code", ""),
                message = payload.optString("message", ""),
                fatal = payload.optBoolean("fatal", false)
            )
            "CAPTCHA_REQUEST" -> Event.CaptchaRequest(
                mode = payload.optString("mode", "auto"),
                redirectUri = payload.optString("redirect_uri", ""),
                sessionToken = payload.optString("session_token", "")
            )
            "CAPTCHA_DONE" -> Event.CaptchaDone(
                success = payload.optBoolean("success", false),
                error = payload.optString("error", "").takeIf { it.isNotBlank() }
            )
            else -> null
        }
    }
}
