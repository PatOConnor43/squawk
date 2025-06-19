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

## Update

I'm putting this on ice for now. There are too many problems that I knew would be difficult to solve but I wanted to run into the wall anyway. Here are some of the problems I ran into:
- Using a variable as a key or value in a call to WithField makes is pretty difficult to resolve. Maybe you get lucky and it's a constant that you can look up with the LSP but that isn't guranteed. This goes the same (but differently) for function calls.
- Gopls is helpful in the wrong ways. I was really hoping to build  a series of "pointers" to logging fields. I was hoping that calling `References` with the language server would allow me to build that graph of logging fields. The speceific problem is that when you call `References` on a variable, you might actually also get references _after_ a variable is reassigned. Consider this example:
```go
l := logger().WithField("1", "1")
l = l.WithField("2", "2")
l.WithField("3", "3").Info("Hello")
```

I was hoping that calling `References` on `l` would only give me the second reference on the second line, then I could call references again on the first reference on the second line. Instead, I get all three references. This is a problem because I can't follow the specific chain of references. A work around could be to pre-process the references and see if there are any assignments between the references, but I don't know if that would work in all cases.

Anyway, it was a very fun project to work on and I learned a ton about Treesitter and the Language Server Protocol. I would be surprised if this is the last time I try to do some kind of static code analysis with Treesitter and the LSP.
