# Code Processing

这个板块负责把代码仓库加工成结构化代码块。

计划中的处理顺序：

1. 扫描仓库中的源文件。
2. 按语言选择 Tree-sitter 解析器，目前支持 Java、Python、JavaScript 和 TypeScript/TSX。
3. 把文件头、类型、成员和初始化代码切成适合搜索的代码块。
4. 把代码块交给混合搜索板块建立索引。

## Java 切块范围

- 文件和类型：`file`、`class`、`interface`、`enum`、`annotation`、
  `record`、`module`、`anonymous_class`。
- 成员：`method`、`constructor`、`field`、`record_component`、
  `enum_constant`、`annotation_element`。
- 初始化代码：`static_initializer`、`initializer`。

类型块只包含文档注释、注解、修饰符和声明头；方法、构造函数及初始化块包含完整代码。
一条多字段声明会生成多个符号，但只生成一个共享代码块，并在 `symbol_ids` 和
`symbol_names` 中保留全部关联。

包声明、导入、注解使用、参数、局部变量和 Lambda 不单独成为符号：文件级信息进入
`file` 块，其余内容保留在所属声明中。

## Python 切块范围

- 文件头：模块说明、import 和首个声明之前的其他内容；
- 类：保存装饰器和类声明头，不重复保存方法体；
- 函数：保存普通函数、异步函数、方法及完整实现；
- 符号名包含模块路径，例如`orders/service.py`中的类会命名为
  `orders.service.OrderService`；嵌套声明继续追加`外层.内层`，避免不同文件同名符号混淆。

当前没有为 Python 的赋值、全局变量或 import 单独建符号；它们仍可在所属代码块中搜索。

## JavaScript 切块范围

- `.js` 文件使用独立的 Tree-sitter JavaScript 语法解析器；
- 保存文件头、类、类方法和普通函数；
- `const health = () => checkHealth()`这类单变量箭头函数也会生成函数块；
- 函数块记录直接调用、成员调用、实参数量，以及`this.method()`、
  `new Service().method()`和`Service.method()`这类能够直接确认的接收者。

一个 JavaScript 文件语法错误时只记录该文件错误，不阻止同仓库其他文件处理。当前阶段
还不解析解构形式的函数赋值、对象字面量方法、CommonJS模块类型和动态原型修改；普通变量
接收者保持未知。JavaScript已经能用于结构化搜索和基础调用线索，
但类型关系精度暂时低于 Java 和 Python。

## TypeScript 与 TSX 切块范围

- `.ts` 与 `.tsx` 都归为`typescript`，但分别使用 TypeScript 和 TSX 语法；
- 与 JavaScript 共享类、方法、函数、箭头函数和调用提取规则；
- 额外保存`interface`、`enum`和`type_alias`代码块；
- 接口方法签名也单独保存，并记录声明参数数量，供重写关系消歧；
- JSX 可以正常解析，不会因为标签语法把整个文件判为错误；
- NestJS 的控制器、HTTP 路由、消息入口、定时任务、Guard和Middleware由入口工具提供位置线索。

TypeScript现在会从函数参数、显式变量类型、`new Service()`和NestJS构造函数参数属性中取得
接收者类型。仓库汇总时还会解析静态ES Module命名导入及别名，例如
`import { OrderService as Service } from "./orders"`。JavaScript/TypeScript静态CommonJS也已
解析：解构`require`等价命名导入，整模块`require`和`import * as`支持`orders.OrderService`
成员。默认导入只在目标模块内有一个声明类型时解析；多个声明类型保持未知，避免猜默认导出。
动态`require`、动态导入、运行时`module.exports`改写、泛型约束、接口装饰器参数含义和依赖
注入运行时绑定仍不推断；接收者类型为空时必须读取固定源码快照核实。

TypeScript的接口继承、类继承与类实现会分别进入`EXTENDS`和`IMPLEMENTS`关系。类方法与
仓库内祖先类/接口存在同名，且固定参数数、必填参数数和rest形状相同时生成`OVERRIDES`候选。
调用关系允许省略`?`或默认值参数，并允许rest接收更多实参。泛型约束、结构类型兼容和运行时
装饰器绑定仍可能改变真实语义，所以关系必须回到源码核实。

## 静态调用名称

Java方法、构造函数和初始化块会记录调用名称、行号、参数个数，以及能够直接确认的
接收者类型；Python函数会记录直接调用`fetch()`和属性调用`service.fetch()`的最后一段
名称，也会识别`OrderService().fetch()`这类明确构造出来的接收者。Python还能从`__init__`
的参数注解解析`self.service.fetch()`，从带注解赋值解析`local: OrderService = service`
这类局部变量。索引器把这些信息交给Neo4j生成`CALLS`候选关系。

仓库汇总阶段会解析Python明确的模块关系，包括`from x import Type`、导入别名、
`import x as module_alias`和包内相对导入。接收者类型有模块完整名时，Neo4j只连接该模块
里的声明；没有import且仓库存在多个同名类型时保持未知。动态import、运行时改写模块、
星号导入和第三方依赖内部类型暂不推断。

带返回注解的方法可用于Python链式调用解析。例如`factory.create_service().fetch()`会先记录
`Factory.create_service`的查找条件，等仓库成功文件全部处理完，再按其参数规则和
`-> OrderService`返回注解补全外层`fetch`的接收者。返回注解必须能通过当前模块或明确
import解析到仓库内唯一类型；没有注解、同名冲突或动态返回表达式时保持未知。
简单的拆行写法也支持，例如`service = Factory().create_service()`之后调用
`service.fetch()`。这里只跟踪同一函数体中、调用前的顶层直接赋值；如果变量可能在分支或
循环中重新赋值，就保持未知，不把某一条可能路径冒充成确定类型。
子类没有重新声明该方法时，可以沿已经确认的祖先关系使用父类返回注解；子类重写后以
子类声明为准。多个祖先给出冲突返回类型时不模拟完整MRO，保持未知并交给源码复核。

这里故意称为“候选”：`new Service().run()`、`Service.run()`、`this.run()`和同类内无
接收者调用可以按类型缩小范围，Java重载还会按参数个数过滤。Java字段、方法参数和
局部变量具有明确声明类型时，也会按局部变量、参数、字段的遮蔽顺序解析
`service.run()`。增强`for`变量、try-with-resources资源和`catch`参数也按自己的词法作用域
生效，离开作用域后不会继续污染后续调用。`var`、常见泛型类型变量、Lambda推断类型、
继承分派和运行时反射仍保持未知。方法接收者、名称、参数个数和唯一返回类型都能确认时，
支持`factory.service().run()`这类返回值链。单文件先保存待解析条件，仓库成功文件全部
处理完后再统一补全，因此声明在另一个文件也可以解析；同名短类型出现不同返回结果时
会按显式`import`、同包类型、唯一通配`import`和仓库全局唯一短名依次限定。仍有冲突时
保持未知，不选择任意一个。Neo4j同时保存接收者完整类型，有完整名时不会退回短名匹配。
因此调用关系用于缩小排查范围，不能替代读取固定快照源码。

Java可变参数（`String... parts`）声明会记录varargs标记；调用处实参个数大于等于声明参数
个数时都能生成边（`log("a")`与`log("a","b")`均正确）。同一对调用者在图上合并为一条边。

Python函数会分别记录调用者需要传入的最少参数数、最多参数数，以及是否存在`*args`。
类方法的首个`self`或`cls`不计入调用参数；默认参数允许少传，但不能超过声明上限；只有
`*args`允许继续多传位置参数，`**kwargs`只接收命名参数，不会错误放宽位置参数数量。
调用点还会区分位置参数与明确的`name=value`关键字参数，因此`def f(*, token)`不会匹配
`f(1)`，`def f(value, /)`也不会匹配`f(value=1)`。遇到`f(*values)`或`f(**values)`时，
展开后的名称和数量只有运行时才知道，图索引会保守保留候选。这些规则用于排除明显
不可能的同名函数，仍不能替代Python运行时绑定和源码复核。

## Java类型关系

类、接口、枚举、record和注解声明块会记录`extends`/`implements`的原始类型名。仓库内
全部文件处理完后，按import和包名解析成完整类型名，并在Neo4j写入：

- `EXTENDS`：类继承父类，接口继承父接口。
- `IMPLEMENTS`：类、枚举、record实现接口。
- `OVERRIDES`：子类型方法与父类型或接口中同名同参数个数的方法连接。

方法块继承所属类型的祖先集合，便于后续查询沿继承链展开。无法解析的外部类型不会
生成关系边，只保留在源码内容中。

## Python类型关系

Python类声明块会记录直接基类短名。仓库内基类短名全局唯一时生成`EXTENDS`边，子类函数
按祖先集生成`OVERRIDES`边。出现同名基类冲突或基类来自外部依赖时不生成边，也不做部分
猜测；Python的MRO、装饰器生成的类和动态基类表达式暂不解析。

动态分派查询把基础方法短名对应到仓库内的全部直接覆盖实现。候选来自`OVERRIDES`边，
仅覆盖本仓库已索引代码；接口方法来自依赖库或运行时反射生成的实现不会出现在候选中，
因此没有候选不等于没有其他运行时实现。

