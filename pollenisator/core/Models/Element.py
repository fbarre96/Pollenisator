"""Element parent Model. Common ground for every model"""

from bson.objectid import ObjectId

class Element(object):
    """
    Parent element for all model. This class should only be inherited.

    Attributes:
        coll_name:  collection name in pollenisator database
    """
    coll_name = None

    def __init__(self, _id, parent, tags, infos):
        """
        Constructor to be inherited. Child model will all use this constructor.

        Args:
            _id: mongo database id
            parent: a parent mongo id object for this model.
            tags: a list of tags applied on this object
            infos: a dicitonnary of custom information 
        """
        # Initiate a cachedIcon for a model, not a class.
        self._id = _id
        self.tags = tags
        self.parent = parent
        self.infos = infos
        self.cachedIcon = None


    def getDetailedString(self):
        """To be inherited and overriden
        Returns a detailed string describing this element. Calls __str__ of children by default.
        Returns:
            string
        """
        return str(self)

