# 固定候选 GLM 实验

使用 result.json 中“用户登录”的同一批100条融合候选，不再次召回。
三个目标 executeLogin、LoginController.login、onAccessDenied 分别处于36、63、87名，
其代码均未超过API的6000字符截断阈值。

初次请求失败，耗时38.517秒。第二次加入仅结构诊断后，耗时35.067秒，
确认 finish_reason=length，排序正文0字符，reasoning_content有8349字符。
说明2048输出额度下没有完成最终排序，不能把这次失败解释为排序准确性差。
未保存或输出远端推理正文。

随后仅在独立实验请求中把max_tokens提高到8192，等待时间设为180秒。
线上仍是10候选、2048输出额度和60秒socket超时，未改动。
最新结果见result.api.json，脚本为api_benchmark.py。

8192额度下成功返回100个合法排序编号，finish_reason=stop，耗时109.126秒。
LoginController.login从63升至1，FormFilter.onAccessDenied从87升至3，
FormFilter.executeLogin从36升至4，FormFilter.createToken从52升至5。
说明这一样本在提供充分候选与输出额度后可以找出目标；不代表其他查询也有相同效果。
与本地模型的对照同时改变了模型、输入格式和输入长度，不能只归因于模型参数能力。
