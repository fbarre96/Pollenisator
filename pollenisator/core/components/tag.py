class Tag:
    def __init__(self, *args, **kwargs):
        if isinstance(args[0], tuple) or isinstance(args[0], list):
            name = args[0][0]
            color = args[0][1]
            level = args[0][2]
            try:
                notes = args[0][3]
            except IndexError:
                notes = ""
        elif isinstance(args[0], Tag):
            name = args[0].name
            color = args[0].color
            level = args[0].level
            notes = args[0].notes
        elif isinstance(args[0], str):
            name = args[0]
            color = kwargs.get("color", None)
            level = kwargs.get("level", None)
            notes = kwargs.get("notes", None)
        elif isinstance(args[0], dict):
            name = args[0].get("name", "")
            color = args[0].get("color", None)
            level = args[0].get("level", None)
            notes = args[0].get("notes", None)
        else:
            raise ValueError("Tag constructor can't handle this type of argument: "+str(type(args[0]))+ ";"+str(args[0]))
        if kwargs.get("color", None) is not None:
            color = kwargs.get("color", None)
        if kwargs.get("level", None) is not None:
            level = kwargs.get("level", None)
        if kwargs.get("notes", None) is not None:
            notes = kwargs.get("notes", None)
        self.name = name
        self.color = color if color is not None else "transparent"
        self.level = level if level is not None else "info"
        self.notes = notes if notes is not None else ""

    def getData(self):
        return {"name": self.name, "color": self.color, "level": self.level, "notes": self.notes}

    @classmethod
    def getSearchableTextAttribute(cls):
        return ["name"]