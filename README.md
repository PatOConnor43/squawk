# Squawk

Squawk is a proof of concept project that attempts to do static code analysis by using a Language Server and Treesitter. The specific goal is to statically analyze Go Logrus logging calls to find the messages and fields that are being logged.

This might sound like a silly task.

> "Why can't you just use grep?"

This project is trying to answer these questions:
- What log messages are being logged?
- What level are they logged at?
- What fields are being logged with each message?

That last one is probably the most difficult to answer. Is order to do it accurately, you need to track:
- Where loggers are created?
- Where is WithField/WithFields called?
- Is a logger being aliased with a different name?
- Is a logger being passed around as a function argument?

These feel like much more difficult questions to answer if you're just using grep, but maybe using a Language Server and Treesitter can help.


## The plan

### Finding log messages

An idea is to open every Go file in the project, then parse it with Treesitter looking for "Info", "Warn", "Error", etc. Here's an example treesitter query:
```scm
(call_expression
  function: (selector_expression
    field: (field_identifier) @method (#any-of? @method "Debug" "Debugf" "Info" "Infof" "Warn" "Warnf" "Error" "Errorf" "Fatal" "Fatalf" "Panic" "Panicf")
  )
  arguments: (argument_list) @arguments
)
```
Once we find all the matches, we can use the LSP to see what we're actually calling this method on. We're only interested in `*logrus.Entry` and not the `fmt` package for instance. We can do this my making a `hover` request to the LSP and (unfortunately) matching the result with a regex that looks like this:
```
func\s\(\w+\s\*logrus\.Entry\)\s(Debug|Info|Warn|Error|Fatal|Panic|Debugf|Infof|Warnf|Errorf|Fatalf|Panicf)\(\w+\s\.\.\.interface\{\}\)
```

Great, we've found every call to a logrus method.

### Finding log fields

Finding the fields is going to be pretty similar. We can look for `WithField` using treesitter and `hover`. Here's an example treesitter query:
```scm
(call_expression
  function: (selector_expression
    operand: (call_expression
      arguments: (argument_list
        "("
        [(identifier) (raw_string_literal) (interpreted_string_literal)] @arguments.key
        ","
        [(identifier) (raw_string_literal) (interpreted_string_literal)] @arguments.value
        ")"
      )
    )
    field: (field_identifier) @method (#eq? @method "WithField")
  )
)
```

### Finding loggers

This is more difficult thanks to aliasing. We want to track loggers in all of these scenarios:
- Functions that return `*logrus.Entry`
- Variables that are assigned from those functions
  - `log := logger()`
- Invocations of those functions that aren't saved as a variable, just used and discarded
  - `logger().Info("Hello")`
- Functions that take `*logrus.Entry` as an argument

Each of these cases are distinct and will need separate mixing of treesitter queries and LSP requests.

# Does it work?

No, not yet. Maybe never.

