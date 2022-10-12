from pollenisator.server.permission import permission

@permission("user")
def getModuleInfo():

    return {"registerLvls": ["AD:onFirstUserOnDC", "AD:onFirstAdminOnDC",  "AD:onNewUserOnDC", "AD:onNewAdminOnDC", 
                            "AD:onFirstUserOnComputer", "AD:onFirstAdminOnComputer", "AD:onNewUserOnComputer", "AD:onNewAdminOnComputer"]}