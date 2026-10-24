export const name = "dsh-secure-push-guard";

/**
 * 推送前强制安检的事前硬门控 —— 轮次级强制。
 *
 * 挂在 `tools/pre-execute` 瀑布最前（prepend），拦截 `git push` 命令（统一拦，不限 remote），
 * 检查「本轮」是否已调用 secret-scan skill（安检）。没调就弹 ask 让人工放行。
 *
 * 与 secure-push-workflow skill 互补，各管一段、互不替代：
 *   - 本插件管「动作门控」：没跑安检就别 push（堵「忘了 scan」）。
 *   - skill 管「结果门控」：跑了安检后按 findings 决策（堵「有发现还硬推」）。
 * 结果门控无法在 pre-execute 落地——插件看不到 scan 的输出（findings 计数），只能看到「有没有跑安检」这个动作。
 *
 * 判定依据：**每轮**（最近一次 user/message 之后）是否已调用 secret-scan。
 * 不是「会话里调过一次就永久放行」，而是「每一轮 push 前都要先安检」。
 *
 * 「已安检」信号：本轮内 tool/call 出现 `name === "skill"` 且 `arguments.name === "secret-scan"`。
 * （DSH 里 skill 工具调用的 tool/call 事件 data 结构为 { name: "skill", arguments: "<JSON 字符串>" }，
 *   其中 arguments 是序列化后的 JSON 字符串、非对象，必须 JSON.parse 后再取 name。）
 */
export function apply(ctx, config = {}) {
  const logger = ctx.logger("secure-push-guard");

  // 「安检」skill：本轮调用它 = 满足「已安检」
  const scanSkills = new Set(config.scanSkills ?? ["secret-scan"]);

  // git push 命令：统一拦，不限 remote（用户在弹窗里人工决定是否放行）
  const PUSH_PATTERN = /\bgit\s+push\b/;

  // 判定「本轮」是否已调 secret-scan：从后往前扫事件，遇到「本轮的用户消息」就停；
  // 停之前若见过 skill 工具调用且 name 指向 secret-scan = 本轮已安检。
  const hasScannedThisTurn = (agent) => {
    if (agent == null || agent.session == null) return true; // 无会话信息时不拦，避免误伤
    try {
      const events = agent.session.snapshotEvents();
      for (let seq = events.length - 1; seq >= 0; seq--) {
        const event = events[seq];
        if (event == null) continue;
        // 本轮起点 = 最近一次 user/message（source.kind === "user"）。走到这里说明本轮内还没安检。
        if (event.type === "user/message" && event.data?.source?.kind === "user") {
          return false;
        }
        if (event.type === "tool/call") {
          const d = event.data;
          // skill 工具调用：name === "skill" 且 arguments.name 指向 secret-scan。
          // 注意：tool/call 事件的 data.arguments 是 JSON 字符串（非对象），必须 parse 后再取 name。
          if (d?.name === "skill") {
            let args = d?.arguments;
            if (typeof args === "string") {
              try { args = JSON.parse(args); } catch { args = null; }
            }
            if (args != null && scanSkills.has(args?.name)) {
              return true; // 本轮内调过安检 skill
            }
          }
        }
      }
      return false;
    } catch (e) {
      logger.warn(`secure-push-guard: hasScannedThisTurn failed: ${e?.message ?? e}`);
      return true;
    }
  };

  // 从 exec.arguments 提取命令文本
  const commandText = (exec) => {
    const a = exec?.arguments;
    if (a == null) return "";
    return String(a.command ?? a.cmd ?? a.script ?? "");
  };

  ctx.on("tools/pre-execute", async (exec, next) => {
    const tool = exec?.name;

    // 只拦 bash/pwsh 里的 git push
    if (tool !== "bash" && tool !== "pwsh") return next();

    const text = commandText(exec);
    if (!PUSH_PATTERN.test(text)) return next();

    // 本轮已调 secret-scan → 放行
    if (hasScannedThisTurn(exec.agent)) {
      logger.info(`secure-push-guard: allow git push — secret-scan done this turn`);
      return next();
    }

    // 本轮未安检 → 弹窗人工放行
    logger.info(`secure-push-guard: deny git push — no secret-scan this turn`);
    return {
      kind: "ask",
      reason: `⚠️ 本轮未跑 secret-scan 安检。是否直接 push（跳过安检）？【允许】= 直接 push，跳过安检；【拒绝】= 先调 secret-scan 安检再 push。命令：${text.slice(0, 120)}`
    };
  }, { prepend: true });
}

export default apply;
