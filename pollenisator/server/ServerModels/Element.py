from pollenisator.core.Components.mongo import MongoCalendar
from bson import ObjectId

class ServerElement(object):
    

    def addTag(self, newTag, overrideGroupe=True):
        """Add the given tag to this object.
        Args:
            newTag: a new tag as a string to be added to this model tags
            overrideGroupe: Default to True. If newTag is in a group with a tag already assigned to this object, it will replace this old tag.
        """
        tags = self.tags
        if newTag not in self.tags:
            mongoInstance = MongoCalendar.getInstance()
            for group in mongoInstance.getTagsGroups():
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
            mongoInstance.connectToDb(self.pentest)
            mongoInstance.doRegisterTag(newTag)
            mongoInstance.update(self.__class__.coll_name, {"_id":ObjectId(self.getId())}, {"$set":{"tags":tags}})

    def updateInfos(self, newInfos):
        """Change all infos stores in self.infos with the given new ones and update database.
        Args:
            newInfos: A new dictionnary of custom information
        """
        if "" in newInfos:
            del newInfos[""]
        self.infos.update(newInfos)
        mongoInstance = MongoCalendar.getInstance()
        ret = mongoInstance.update(self.__class__.coll_name, {"_id":ObjectId(self.getId())}, {"$set":{"infos":self.infos}})
    
    def getId(self):
        return self._id