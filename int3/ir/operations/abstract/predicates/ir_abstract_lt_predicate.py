from .ir_abstract_predicate import IrAbstractPredicate


class IrAbstractLtPredicate(IrAbstractPredicate):
    def __str__(self):
        return f"{self.left_operand} < {self.right_operand}"
