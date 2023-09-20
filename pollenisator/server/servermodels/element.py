

from datetime import datetime
from pollenisator.core.components.mongo import DBClient
from bson import ObjectId
from pollenisator.server.permission import permission

REGISTRY = {}

def register_class(target_class):
    """Register the given class
    Args:
        target_class: type <class>
    """
    REGISTRY[target_class.__name__] = target_class


class MetaElement(type):
    def __new__(meta, name, bases, class_dict):
        cls = type.__new__(meta, name, bases, class_dict)
        if name not in REGISTRY:
            register_class(cls)
        return cls



class ServerElement(metaclass=MetaElement):

    def __init__(self, *args, **kwargs):
        self.repr_string = self.getDetailedString()

    @classmethod
    def classFactory(cls, name):
        for class_name in REGISTRY.keys():
            if name.endswith("s"):
                name = name[:-1]
            if class_name.lower().replace("server","") == name.lower():
                return REGISTRY[class_name]


    @classmethod
    def replaceAllCommandVariables(cls, pentest, command, data):
        for class_name in REGISTRY.keys():
            command = REGISTRY[class_name].replaceCommandVariables(pentest, command, data)
        return command

    @classmethod
    def replaceCommandVariables(cls, pentest, command, data):
        return command

    @classmethod
    def getClassWithTrigger(cls, trigger):
        for class_name in REGISTRY.keys():
            trigger_test = trigger
            if len(trigger.split(":")) == 3:
                trigger_test = ":".join(trigger.split(":")[:2])
            triggers = REGISTRY[class_name].getTriggers()
            triggers_test = [":".join(trigger.split(":")[:2]) for trigger in triggers]
            if trigger_test in triggers_test:
                return REGISTRY[class_name]

    @classmethod
    def completeDetailedString(cls, data):
        return ""

    def getDetailedString(self):
        return str(self)

    @classmethod
    def fetchObjects(cls, pentest, pipeline):
        """Fetch many commands from database and return a Cursor to iterate over model objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on model objects
        """
        dbclient = DBClient.getInstance()
        ds = dbclient.findInDb(pentest, cls.coll_name, pipeline, True)
        if ds is None:
            return None
        for d in ds:
            # disabling this error as it is an abstract function
            yield cls(pentest, d)  #  pylint: disable=no-value-for-parameter
    
    @classmethod
    def fetchObject(cls, pentest, pipeline):
        """Fetch many commands from database and return a Cursor to iterate over model objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on model objects
        """
        dbclient = DBClient.getInstance()
        d = dbclient.findInDb(pentest, cls.coll_name, pipeline, False)
        if d is None:
            return None
        return cls(pentest, d) 
    
    def getTags(self):
        if self is None:
            return
        dbclient = DBClient.getInstance()
        tags = dbclient.findInDb(self.pentest, "tags", {"item_id": ObjectId(self.getId())}, False)
        if tags is None:
            return []
        return tags["tags"]
    
    def addTag(self, newTag, override=True):
        tags = self.getTags()
        if isinstance(newTag, tuple):
            newTagLevel = newTag[2] if newTag[2] is not None else "info"
            newTagColor = newTag[1] if newTag[1] is not None else "transparent"
            newTag = newTag[0]
        else:
            newTagColor = "transparent"
            newTagLevel = "info"
        if newTag not in tags:
            dbclient = DBClient.getInstance()
            for group in dbclient.getTagsGroups():
                if newTag in group:
                    i = 0
                    len_tags = len(tags)
                    while i < len_tags:
                        if tags[i] in group:
                            if override:
                                tags.remove(tags[i])
                                i -= 1
                            else:
                                continue
                        len_tags = len(tags)
                        i += 1
            tags.append((newTag, newTagColor, newTagLevel))
            self.setTags(tags)
            dbclient.doRegisterTag(self.pentest, newTag, newTagColor, newTagLevel)

    def setTags(self, tags):
        """Set the model tags to given tags
        Args:
            tags: a list of string describing tags.
        """
        dbclient = DBClient.getInstance()
        old_tags_res = self.getTags()
        old_tags = set()
        for old_tag in old_tags_res:
            old_tag = str(old_tag[0]) if not isinstance(old_tag, str) else old_tag
            old_tags.add(old_tag)
        new_tags = set()
        for tag in tags:
            if (isinstance(tag, tuple) or isinstance(tag, list)) and len(tag) == 3:
                tag_name = tag[0]
                dbclient.doRegisterTag(self.pentest, name=tag_name, color=tag[1], level=tag[2])
            else:
                tag_name = tag
                dbclient.doRegisterTag(self.pentest, tag_name)
            new_tags.add(tag_name)
        deleted_tags = old_tags - new_tags
        added_tags = new_tags - old_tags
        target_type = self.__class__.name if hasattr(self.__class__, "name") else self.__class__.coll_name
        for tag in deleted_tags:
            self.addTagChecks(["tag:onRemove:"+str(tag_name)],{"target_iid":ObjectId(self.getId()), "target_type":target_type, "tags":tags, "target_data":self.getData()})
        for tag in added_tags:
            self.addTagChecks(["tag:onAdd:"+str(tag_name)],{"target_iid":ObjectId(self.getId()), "target_type":target_type, "tags":tags, "target_data":self.getData()})
        tags = dbclient.updateInDb(self.pentest, "tags", {"item_id": ObjectId(self.getId())}, {"$set":{"tags":tags, "date": datetime.now(), "item_id":ObjectId(self.getId()), "item_type":target_type}}, upsert=True)

    def updateInfos(self, newInfos):
        """Change all infos stores in self.infos with the given new ones and update database.
        Args:
            newInfos: A new dictionnary of custom information
        """
        if "" in newInfos:
            del newInfos[""]
        self.infos.update(newInfos)
        dbclient = DBClient.getInstance()
        ret = dbclient.updateInDb(self.pentest, self.__class__.coll_name, {"_id":ObjectId(self.getId())}, {"$set":{"infos":self.infos}})
    
    def getId(self):
        return self._id

    def __str__(self):
        return str(self.__class__) +":"+str(self._id)

    def __repr__(self):
        """For `print` and `pprint`"""
        return self.to_str()
    
    @classmethod
    def add_tag_check(cls, pentest, lvls, infos):
        from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
        from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance
        dbclient = DBClient.getInstance()
        search = {"lvl":{"$in": lvls}}
        pentest_type = dbclient.findInDb(pentest, "settings", {"key":"pentest_type"}, False)
        if pentest_type is not None:
            search["pentest_types"] = pentest_type["value"]
        # query mongo db commands collection for all commands having lvl == network or domain 
        checkitems = CheckItem.fetchObjects(search)
        if checkitems is None:
            return
        for check in checkitems:
            CheckInstance.createFromCheckItem(pentest, check, str(infos.get("target_iid")), infos.get("target_type"), infos)
    
    def addTagChecks(self, lvls, infos):
        return self.__class__.add_tag_check(self.pentest, lvls, infos)
        

    @classmethod
    def apply_retroactively_custom(cls, pentest, check_item):
        dbclient = DBClient.getInstance()
        if check_item.lvl.startswith("tag:onAdd:"):
            tag_test = check_item.lvl.split(":")[2]
            taggeds = dbclient.findInDb(pentest, "tags", {}, True)
            for tagged in taggeds:
                for tag_name in tagged.get("tags", []):
                    if not isinstance(tag_name, str):
                        tag_name = tag_name[0]
                    if tag_name != tag_test:
                        continue
                    element_cls = cls.classFactory(tagged.get("item_type",""))
                    item_tagged = element_cls.fetchObject(pentest, {"_id":ObjectId(tagged.get("item_id"))})
                    if item_tagged is None:
                        continue
                    infos = {"target_iid":ObjectId(item_tagged.getId()), "target_type":tagged.get("item_type",""), "tags":tagged, "target_data":item_tagged.getData()}
                    cls.add_tag_check(pentest, [check_item.lvl], infos)


    @classmethod
    def getTriggers(cls):
        return ["tag:onAdd:str", "tag:onRemove:str"]
    
   
@permission("user")
def getTriggerLevels():
    """Return the list of trigger levels of this object.
    Returns:
        list: A list of trigger levels as string
    """
    ret = set()
    for class_name in REGISTRY.keys():
        ret = ret.union(set(REGISTRY[class_name].getTriggers()))
    return sorted(list(ret))