# 针对 Plan 3.5 的补充工程化落地预警 (Tech Warnings)

你问我“确定吗”，这确实让我重新审视了 Plan 3.5 在**代码实际落地层面的工程细节**。如果脱离架构蓝图，直接动手敲代码，Plan 3.5 有 3 个极易踩坑的“工程暗雷”。

在正式开发前，请务必注意以下几点，并将其作为具体实现的约束：

## 1. 致命陷阱：嵌套线程池导致的死锁 (Nested ThreadPool Starvation)
- **隐患**：Plan 3.5 要求在 API Client（如 `ThreatFoxClient`）内部也实现并发。如果我们为了省事，在内层代码继续 `with ThreadPoolExecutor() as executor:`，这在单条告警处理时没问题；但如果在 `batch_plan_full` 模式下，外层（Coordinator/Baseline）已经是线程池，内层又是线程池，几十个 HTTP 请求会瞬间耗尽 Python 进程的可用 Worker 导致**互相等待和死锁**。
- **规避方案**：**坚决不要使用嵌套线程池**。既然要做深层 I/O 优化，请直接把底层的请求库从 `requests` 替换为异步的 `httpx`，并使用 `asyncio.gather` 来打散 Client 内部的多 Payload 请求。这才是高并发网络 I/O 的终极解法。

## 2. 架构痛点：工具层 (Tooling) 如何优雅地注入 LLM 实例
- **隐患**：Plan 3.5 要求把 `extract_claim_candidates_from_page` 升级为“轻量 LLM 语义抽取”。但在 LangChain 中，目前它只是一个简单的 `@tool` 静态函数。如果要在它内部调用 LLM，最粗暴的做法是每次进入函数都 `load_config()` 然后新实例化一个大模型对象，这极其消耗性能且完全无法被 `pytest` Mock。
- **规避方案**：必须对这部分 Tool 进行面向对象重构。将需要调用 LLM 的探索工具改造为继承自 `BaseTool` 的类（例如 `class LLMExtractionTool(BaseTool): llm: Any`），在 `coordinator.py` 初始化整个系统时，把全局唯一复用的 LLM 实例注入进去。

## 3. 成本失控：轻量 LLM 抽取的 Token 爆炸风险
- **隐患**：即便引入了“轻量 LLM”，如果把 `fetch_page_content` 截断出来的 6000-8000 个字符原封不动塞给大模型做 Pydantic 实体提取，一条告警查 3 个网页，10 条告警的 Batch 瞬间就会烧掉几十万 Token，而且长文本提取的 Latency（首字响应时间）根本压不下来。
- **规避方案**：Plan 3.5 提到的“保留预过滤”必须执行到极致。在把文本交给 LLM 之前，必须先用一个极度轻量级的本地滑动窗口或词袋匹配（Bag of Words），只把那些**包含任意 IOC（IP/Hash等）或安全词汇（C2、APT、Inject等）及其上下文各 100 字符的段落**拼接起来交给 LLM。把 8000 字浓缩到 1000 字以内的“高浓度上下文”再做 Semantic Extraction，速度和成本才能做到双赢。

---
**总结**：Plan 3.5 的宏观方向绝对正确，但这三个工程细节决定了它落地后是“玩具”还是“神兵”。这几点补充意见已经写入，你们在执行 Phase 2 和 Phase 4 时请务必绕开这些坑！