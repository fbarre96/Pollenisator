"""Controller for defect object. Mostly handles conversion between mongo data and python objects"""

from pollenisator.core.controllers.controllerelement import ControllerElement


class DefectController(ControllerElement):
    """Inherits ControllerElement
    Controller for defect object. Mostly handles conversion between mongo data and python objects"""

    def doUpdate(self, values):
        """
        Update the Defect represented by this model in database with the given values.

        Args:
            values: A dictionary crafted by DefectView containg all form fields values needed.

        Returns:
            The mongo ObjectId _id of the updated Defect document.
        """
        self.model.title = values.get("Title", self.model.title)
        self.model.synthesis = values.get("Synthesis", self.model.synthesis)
        self.model.description = values.get("Description", self.model.description)
        self.model.ease = values.get("Ease", self.model.ease)
        self.model.impact = values.get("Impact", self.model.impact)
        self.model.risk = values.get("Risk", self.model.risk)
        self.model.redactor = values.get("Redactor", self.model.redactor)
        mtype = values.get("Type", None)
        if mtype is not None:
            mtype = [k for k, v in mtype.items() if v == 1]
            self.model.mtype = mtype
        self.model.language = values.get("Language", self.model.language)
        self.model.notes = values.get("Notes", self.model.notes)
        self.model.fixes = values.get("Fixes", self.model.fixes)
        self.model.infos = values.get("Infos", self.model.infos)
        for info in self.model.infos:
            self.model.infos[info] = self.model.infos[info][0]
        # Updating

        self.model.update()

    def doInsert(self, values):
        """
        Insert the Defect represented by this model in the database with the given values.

        Args:
            values: A dictionary crafted by DefectView containing all form fields values needed.

        Returns:
            {
                '_id': The mongo ObjectId _id of the inserted command document.
                'nbErrors': The number of objects that has not been inserted in database due to errors.
            }
        """
        title = values["Title"]
        synthesis = values["Synthesis"]
        description = values["Description"]
        ease = values["Ease"]
        impact = values["Impact"]
        redactor = values["Redactor"]
        mtype_dict = values["Type"]
        mtype = [k for k, v in mtype_dict.items() if v == 1]
        language = values["Language"]
        target_id = values["target_id"]
        target_type = values.get("target_type", None)
        notes = values["Notes"]
        proof = values["Proof"]
        fixes = values["Fixes"]
        proofs = []
        tableau_from_ease = {"Easy": {"Minor": "Major", "Important": "Major", "Major": "Critical", "Critical": "Critical"},
                             "Moderate": {"Minor": "Important", "Important": "Important", "Major": "Major", "Critical": "Critical"},
                             "Difficult": {"Minor": "Minor", "Important": "Important", "Major": "Major", "Critical": "Major"},
                             "Arduous": {"Minor": "Minor", "Important": "Minor", "Major": "Important", "Critical": "Important"}}
        risk = tableau_from_ease.get(ease,{}).get(impact,"N/A")
        self.model.initialize(target_id, target_type, title, ease,
                              impact, risk, redactor, mtype, notes, proofs)
        ret, _ = self.model.addInDb()
        # Update this instance.
        # Upload proof after insert on db cause we need its mongoid
        if proof.strip() != "":
            self.model.uploadProof(proof)
        return ret, 0  # 0 erros

    def addAProof(self, formValues, index):
        """Add a proof file to model defect.
        Args:
            formValues: the view form values as a dict. Key "Proof "+str(index) must exist
            index: the proof index in the form to insert
        """
        proof_path = formValues["Proof "+str(index)]
        if proof_path.strip() == "":
            return
        resName = self.model.uploadProof(proof_path)
        if index == len(self.model.proofs):
            self.model.proofs.append(resName)
        else:
            self.model.proofs[index] = resName
        # self.model.update()

    def deleteProof(self, ind):
        """Delete a proof file given a proof index
        Args:
            ind: the proof index in the form to delete
        """
        self.model.removeProof(ind)

    def isAssigned(self):
        """Checks if the defect model is assigned to an IP or is global
        Returns:    
            bool
        """
        return self.model.isAssigned()


    def getType(self):
        """Returns a string describing the type of object
        Returns:
            "defect" """
        return "defect"