from .constant import IrBytesConstant, IrIntConstant
from .variable import IrBytesVariable, IrIntVariable

type IrVariable = IrBytesVariable | IrIntVariable
type IrConstant = IrBytesConstant | IrIntConstant

type IrIntType = IrIntConstant | IrIntVariable
type IrBytesType = IrBytesConstant | IrBytesVariable
