# Code Processing

这个板块负责把代码仓库加工成结构化代码块。

计划中的处理顺序：

1. 扫描仓库中的源文件。
2. 用 Tree-sitter 解析 Java 语法树并建立符号层级。
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

