"""Module using Lark parser to parse filter query and return according results"""
from typing import Any, Iterable, List, Tuple
from lark import Lark, Transformer, Tree, exceptions

class Term:
    """A search term, meaning "key.name" == (value) """
    def __init__(self, val: Any) -> None:
        """
        Constructor for the class.

        Args:
            val (Any): The value to be stored in the instance.

        Returns:
            None
        """
        self.val = val

    def __str__(self) -> str:
        """
        Return the string representation of the object.

        Returns:
            str: The string representation of the object.
        """
        return str(self.val)

class TreeToCondition(Transformer):
    """Inherits lark.Transformer
    A Lark Transformer to process the parse-tree returned by lark
    Attributes:
        null: value will be converted to python None
        true: value will be converted to python True
        false: value will be converted to python False
        eq: value will be converted to string "=="
        neq: value will be converted to string "!="
        gt: value will be converted to string ">"
        ge: value will be converted to string ">="
        le: value will be converted to string "<="
        lt: value will be converted to string "<"
        regex: value will be converted to string "||regex||"
        inside: value will be converted to string "in"
        notin: value will be converted to string "not in"
        andcond: value will be converted to string "and"
        orcond: value will be converted to string "or"
        notcond: value will be converted to string "not"
    """
    null = lambda self, _: None
    true = lambda self, _: True
    false = lambda self, _: False
    eq = lambda self, _: "=="
    neq = lambda self, _: "!="
    gt = lambda self, _: ">"
    ge = lambda self, _: ">="
    le = lambda self, _: "<="
    lt = lambda self, _: "<"
    regex = lambda self, _: "||regex||"
    inside = lambda self, _: "in"
    notin = lambda self, _: "not in"
    andcond = lambda self, _: "and"
    orcond = lambda self, _: "or"
    notcond = lambda self, _: "not"

    def term(self, items: Iterable[Any]) -> List[Any]:
        """
        Applied on parse-tree terms objects.

        Args:
            items (Iterable[Any]): The parse-tree term object.

        Returns:
            List[Any]: The given item as a list.
        """
        return list(items)

    def var(self, s: Tuple[Any]) -> Term:
        """
        Applied on parse-tree var objects.

        Args:
            s (Tuple[Any]): The parse-tree var object.

        Returns:
            Term: The given item as a Term.
        """
        (s,) = s
        return Term(s)

    def string(self, s: Tuple[Any]) -> str:
        """
        Applied on parse-tree string objects.

        Args:
            s (Tuple[Any]): The parse-tree string object.

        Returns:
            str: The given item as a string.
        """
        (s,) = s
        return str(s)

    def number(self, n: Tuple[Any]) -> str:
        """
        Applied on parse-tree number objects.

        Args:
            n (Tuple[Any]): The parse-tree number object.

        Returns:
            str: The given item as a string with double quotes around them.
        """
        (n,) = n
        return "\""+str(n)+"\""



class ParseError(Exception):
    """Inherits Exception
    Class to raise parsing error"""

class Parser:
    """
    Class to perform Lark parsing and filter database search.
    Attributes:
        condition_parser: The parsing syntax of Lark is used to search
                        * term: is a (var == value)   
                        * uniopcond: is unary operation (not)
                        * opcond: logical operator on temrs ("and" and "or")       
                        * opregex: the regex operator
                        * STRING: an alphanumeric string with extras characs '.', '[' and ']'
    """

    condition_parser = Lark(r"""
    ?term: "("fixedvalue op fixedvalue")"
                | fixedvalue op fixedvalue
                | STRING opregex ESCAPED_STRING
                | uniopcond term
                | "("uniopcond term")"
                | term opcond term
                | "("term opcond term")"
    uniopcond: "not" -> notcond
    opcond: "and" -> andcond | "or" -> orcond
    op: "==" -> eq | "!=" -> neq | ">" -> gt | "<" -> lt 
        | "<=" -> le | ">=" -> ge | "in" -> inside | "not in" -> notin 
    opregex: "regex" -> regex
    STRING: /[A-Za-z0-9\.\[\]]+/
    fixedvalue: SIGNED_NUMBER -> number
         | "true" -> true
         | "false" -> false
         | "null" -> null
         | ESCAPED_STRING -> string
         | STRING -> var

    %import common.ESCAPED_STRING
    %import common.SIGNED_NUMBER
    %import common.WS
    %ignore WS
    """, start='term', parser="lalr", transformer=TreeToCondition())

    @classmethod
    def help(cls) -> str:
        """Return a string to help typing request by providing examples
        Returns:
            A string of examples
        """
        # pylint: disable=anomalous-backslash-in-string
        return """
Search examples in match (python condition):
type == "port"
type == "port" and port == 443
type == "port" and port regex "443$"
type == "port" and (port == 80 or port == 443)
type == "port" and port != 443
type == "port" and port != 443 and port != 80
type == "defect"
type == "defect" and "Foo" in title
type == "ip" and ip regex "[A-Za-z]"
type == "ip" and ip regex "^1\.2"
type == "tool" and "done" in status
type == "tool" and "done" not in status
type == "tool" and "ready" in status
type == "ip" and infos.key == "ABC"
"""
    def __init__(self, query: str = "") -> None:
        """
        Constructor for the Parser class.

        Args:
            query (str): The query to parse. Defaults to an empty string.

        Raises:
            ParseError: If Lark raises an UnexpectedToken or an UnexpectedCharacters exception.
        """
        try:
            self.parsed = Parser.condition_parser.parse(query)
        except exceptions.UnexpectedToken as e:
            raise ParseError(e) from e
        except exceptions.UnexpectedCharacters as e:
            raise ParseError(e) from e

    def getResult(self) -> Tree:
        """
        Get the result of the parsing.

        Returns:
            Tree: The parsed result.
        """
        return self.parsed
