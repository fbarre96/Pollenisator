from pollenisator.core.components.mongo import DBClient
from bson import ObjectId
import pprint

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
            if trigger in REGISTRY[class_name].getTriggers():
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
    
    def addTag(self, newTag, overrideGroupe=True):
        """Add the given tag to this object.
        Args:
            newTag: a new tag as a string to be added to this model tags
            overrideGroupe: Default to True. If newTag is in a group with a tag already assigned to this object, it will replace this old tag.
        """
        tags = self.tags
        if isinstance(newTag, tuple):
            newTagColor = newTag[1]
            newTag = newTag[0]
        else:
            newTagColor = "white"
        if newTag not in self.tags:
            dbclient = DBClient.getInstance()
            for group in dbclient.getTagsGroups():
                if newTag in group:
                    i = 0
                    len_tags = len(tags)
                    while i < len_tags:
                        if tags[i] in group:
                            if overrideGroupe:
                                tags.remove(tags[i])
                                i -= 1
                            else:
                                continue
                        len_tags = len(tags)
                        i += 1
            tags.append(newTag)
            self.tags = tags
            dbclient.doRegisterTag(self.pentest, newTag, newTagColor)
            dbclient.updateInDb(self.pentest, self.__class__.coll_name, {"_id":ObjectId(self.getId())}, {"$set":{"tags":tags}})

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
    def getTriggers(cls):
        return []
    
   
@permission("user")
def getTriggerLevels():
    """Return the list of trigger levels of this object.
    Returns:
        list: A list of trigger levels as string
    """
    ret = []
    for class_name in REGISTRY.keys():
        ret += REGISTRY[class_name].getTriggers()
    return ret