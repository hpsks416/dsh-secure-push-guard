export const name = "dsh-secure-push-guard";

/**
 * 推送前强制安检 + 强制安全调用 token 的事前硬门控 —— 轮次级强制。
 *
 * 挂在 `tools/pre-execute` 瀑布最前（prepend），拦截 `git push`（统一拦，不限 remote），
 * 两道门控：
 *   1. token 安全：本轮是否「直接读了 G:\KEY token 明文」（Get-Content/read G:\KEY）——读了说明
 *      token 进了 agent 上下文，不安全，应走 push-secure.cmd。
 *   2. 安检：本轮是否调过 secret-scan skill——没调说明没安检。
 * 任一不满足都弹 ask 让人工放行。
 *
 * 判定依据：**每轮**（最近一次 user/message 之后）的 tool/call 历史。
 */
export function apply(ctx, config = {}) {
  const logger = ctx.logger("secure-push-guard");

  const scanSkills = new Set(config.scanSkills ?? ["secret-scan"]);

  const PUSH_PATTERN = /\bgit\s+push\b/;

  // 解析 tool/call 的 arguments（JSON 字符串 → 对象）
  const parseArgs = (d) => {
    if (d?.arguments == null) return null;
    if (typeof d.arguments === "string") {
      try { return JSON.parse(d.arguments); } catch { return null; }
    }
    return d.arguments;
  };

  // 判定「本轮」是否调过 secret-scan（安检）
  const hasScannedThisTurn = (agent) => {
    if (agent == null || agent.session == null) return true;
    try {
      const events = agent.session.snapshotEvents();
      for (let seq = events.length - 1; seq >= 0; seq--) {
        const event = events[seq];
        if (event == null) continue;
        if (event.type === "user/message" && event.data?.source?.kind === "user") return false;
        if (event.type === "tool/call") {
          const d = event.data;
          if (d?.name === "skill") {
            const args = parseArgs(d);
            if (args != null && scanSkills.has(args?.name)) return true;
          }
        }
      }
      return false;
    } catch (e) {
      logger.warn(`secure-push-guard: hasScannedThisTurn failed: ${e?.message ?? e}`);
      return true;
    }
  };

  // 判定「本轮」是否直接读了 G:\KEY token 明文（不安全调用）
  const hasReadTokenThisTurn = (agent) => {
    if (agent == null || agent.session == null) return false;
    try {
      const events = agent.session.snapshotEvents();
      for (let seq = events.length - 1; seq >= 0; seq--) {
        const event = events[seq];
        if (event == null) continue;
        if (event.type === "user/message" && event.data?.source?.kind === "user") return false;
        if (event.type === "tool/call") {
          const d = event.data;
          const args = parseArgs(d);
          if (args == null) continue;
          // pwsh/bash 命令里 Get-Content/cat/type 读 G:\KEY
          if (d?.name === "pwsh" || d?.name === "bash") {
            const cmd = String(args.command ?? args.cmd ?? args.script ?? "");
            if (/G:\\KEY/i.test(cmd) && /(Get-Content|cat\b|type\b)/i.test(cmd)) return true;
          }
          // read 工具直接读 G:\KEY 文件
          if (d?.name === "read") {
            const fp = String(args.file_path ?? "");
            if (/G:\\KEY/i.test(fp)) return true;
          }
        }
      }
      return false;
    } catch (e) {
      logger.warn(`secure-push-guard: hasReadTokenThisTurn failed: ${e?.message ?? e}`);
      return false;
    }
  };

  const commandText = (exec) => {
    const a = exec?.arguments;
    if (a == null) return "";
    return String(a.command ?? a.cmd ?? a.script ?? "");
  };

  ctx.on("tools/pre-execute", async (exec, next) => {
    const tool = exec?.name;
    if (tool !== "bash" && tool !== "pwsh") return next();

    const text = commandText(exec);
    if (!PUSH_PATTERN.test(text)) return next();

    // 门控 1：token 安全 —— 本轮直接读了 G:\KEY token 明文
    if (hasReadTokenThisTurn(exec.agent)) {
      logger.info(`secure-push-guard: deny git push — read G:\KEY token directly this turn`);
      return {
        kind: "ask",
        reason: `⚠️ 本轮直接读了 G:\KEY token 明文（不安全，token 已进 agent 上下文）。是否继续 push？【允许】= 继续（已知风险）；【拒绝】= 改用 push-secure.cmd（token 走脚本，不进上下文）。命令：${text.slice(0, 120)}`
      };
    }

    // 门控 2：安检 —— 本轮没调 secret-scan
    if (!hasScannedThisTurn(exec.agent)) {
      logger.info(`secure-push-guard: deny git push — no secret-scan this turn`);
      return {
        kind: "ask",
        reason: `⚠️ 本轮未跑 secret-scan 安检。是否直接 push（跳过安检）？【允许】= 直接 push，跳过安检；【拒绝】= 先调 secret-scan 安检再 push。命令：${text.slice(0, 120)}`
      };
    }

    logger.info(`secure-push-guard: allow git push — token-safe + secret-scan done this turn`);
    return next();
  }, { prepend: true });
}

export default apply;
