# 海底观测网设备故障管理

这是一个只使用Python标准库和SQLite的模块化原型项目，默认端口为`8337`。领域对象包括站点、资产、链路、遥测、故障事件、恢复动作、出海任务和数据缺口。`app.py`只负责参数解析、依赖组装和服务生命周期，业务状态机与约束集中在`src/rules.py`。

## 模块结构

- `app.py`：命令行参数、依赖组装、启动和信号处理。
- `src/domain.py`：角色、领域异常、身份解析和实体数据结构。
- `src/rules.py`：状态机、角色权限、领域计算、冲突和跨对象校验。
- `src/repository.py`：SQLite建表、查询、事务、乐观锁、审计和幂等键。
- `src/service.py`：用例编排、离线记录合并、版本控制和审计写入。
- `src/http_api.py`：HTTP路由、JSON解析和统一错误响应。
- `src/audit.py`：实体操作审计时间线。
- `static/index.html`：最小演示页面。
- `tests/`：完整流程、规则和失败场景测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8337
```

服务启动时自动建表。`--host`可修改监听地址，`--db`可指定其他SQLite文件。初始化服务不需要单独命令，首次启动即可访问：

```bash
curl http://127.0.0.1:8337/health
```

## 主要接口

- `GET /health`：健康检查。
- `GET /api/<kind>`：按对象类型查询，可用`?status=`过滤。
- `POST /api/<kind>`：创建对象；请求体为JSON。
- `GET /api/entities/<id>`：读取对象当前版本。
- `POST /api/entities/<id>/actions`：提交`{"action":"动作名","data":{...},"expected_version":数字}`。
- `GET /api/audit`：读取审计记录。

身份通过`X-User-Id`和`X-Role`请求头传入，角色和动作权限由规则引擎校验。## 核心流程

建立站点、资产和链路后记录遥测与故障事件，创建恢复动作并跟踪重启、备用链路、出海任务和数据缺口，最后关闭事件。遥测`revise`动作只接受更高修订号，用于处理迟到数据。

## 规则重点

- 同一资产（范围）和故障类型同时只能有一个活动事件：同时提交时先到的生效，后到的收到`200`和活动事件编号（响应带`deduplicated: true`），由`incident_active`唯一键在事务内保证，不重复记审计。
- 事件`resolve`/`confirm_closure`时把受影响资产当前最高遥测修订号记入`closure_basis`作为收口依据。
- 遥测修订号一旦变高（`revise`或更高修订号的新遥测），依据更旧修订号收口的事件立即置为`reconfirm`、`closure_valid=false`，需用`confirm_closure`重新确认（重新校验恢复动作、数据缺口和资产状态，并记录新依据）或`reopen`。
- 恢复动作按`dedupe_key`防止重复执行。
- 事件解决前恢复动作、数据缺口和受影响资产必须达到可关闭状态。
- 状态、修订号、活动槽位和审计在同一事务提交：任一步失败全部回滚；动作支持`Idempotency-Key`请求头，重试返回当前状态且不重复记审计。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

## 局限

项目使用请求头模拟身份、SQLite单机持久化和简化状态机，适合原型演示和流程验证，不替代行业正式系统、设备控制系统或现场安全规程。
