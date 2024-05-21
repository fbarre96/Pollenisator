"""Module Activedirecotry :  ComputerInfos class."""
# coding: utf-8


from typing import Any, Dict, Optional, Union, List


class ComputerInfos():
    """ComputerInfos class."""
    def __init__(self, valuesFromDb: Union['ComputerInfos', Optional[Dict[str, Any]]] = None) -> None:
        """
        Initialize a ComputerInfos object. If valuesFromDb is not provided, an empty dictionary is used. The values for the 
        attributes of the ComputerInfos object are fetched from the valuesFromDb dictionary using the get method.

        Args:
            valuesFromDb (Optional[Dict[str, Union[str, bool, List[str]]]], optional): A dictionary containing the values 
            for the attributes of the ComputerInfos object. Defaults to None.

        Attributes:
            os (str): The os of this ComputerInfos.
            signing (bool): The signing of this ComputerInfos.
            smbv1 (bool): The smbv1 of this ComputerInfos.
            is_dc (bool): The is_dc of this ComputerInfos.
            is_sqlserver (bool): The is_sqlserver of this ComputerInfos.
            secrets (List[str]): The secrets of this ComputerInfos.
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        elif isinstance(valuesFromDb, ComputerInfos):
            valuesFromDb = valuesFromDb.getData()
        self.initialize(valuesFromDb.get("os"), valuesFromDb.get("signing"),valuesFromDb.get("smbv1"), \
                valuesFromDb.get("is_dc"), valuesFromDb.get("secrets", []), valuesFromDb.get("is_sqlserver"))


    def initialize(self, os: Optional[str] = None, signing: Optional[bool] = None, smbv1: Optional[bool] = None, 
                   is_dc: Optional[bool] = None, secrets: Optional[List[str]] = None, 
                   is_sqlserver: Optional[bool] = None) -> 'ComputerInfos': 
        """
        Initialize the ComputerInfos object with the provided values. If a value is not provided, the corresponding attribute 
        is set to None.

        Args:
            os (Optional[str], optional): The os of the ComputerInfos object. Defaults to None.
            signing (Optional[bool], optional): The signing of the ComputerInfos object. Defaults to None.
            smbv1 (Optional[bool], optional): The smbv1 of the ComputerInfos object. Defaults to None.
            is_dc (Optional[bool], optional): The is_dc of the ComputerInfos object. Defaults to None.
            secrets (Optional[List[str]], optional): The secrets of the ComputerInfos object. Defaults to None.
            is_sqlserver (Optional[bool], optional): The is_sqlserver of the ComputerInfos object. Defaults to None.

        Returns:
            ComputerInfos: The initialized ComputerInfos object.
        """
        self.os: Optional[str] = os
        self.signing: Optional[bool] = signing
        self.smbv1: Optional[bool] = smbv1
        self.is_dc: Optional[bool] = is_dc
        self.secrets: List[str] = secrets if secrets is not None else []
        self.is_sqlserver: Optional[bool] = is_sqlserver
        return self

    def getData(self) -> Dict[str, Any]:
        """
        Get the data of the ComputerInfos object as a dictionary. The keys of the dictionary are the attribute names and the 
        values are the corresponding attribute values.

        Returns:
            Dict[str, Union[str, bool, List[str]]]: A dictionary containing the data of the ComputerInfos object.
        """
        return {"os":self.os, "signing": self.signing, "smbv1":self.smbv1, "is_dc":self.is_dc,  "is_sqlserver":self.is_sqlserver, "secrets":self.secrets}
    
    def update(self, values: Dict[str, Any]) -> None:
        """
        Update the ComputerInfos object with the provided values. The values are fetched from the values dictionary using the 
        get method.

        Args:
            values (Dict[str, Any]): A dictionary containing the values to update the ComputerInfos object.
        """
        self.os = values.get("os", self.os)
        self.signing = values.get("signing", self.signing)
        self.smbv1 = values.get("smbv1", self.smbv1)
        self.is_dc = values.get("is_dc", self.is_dc)
        self.is_sqlserver = values.get("is_sqlserver", self.is_sqlserver)
        self.secrets = values.get("secrets", self.secrets)

    @property
    def os(self) -> Optional[str]:
        """
        Gets the os of this ComputerInfos.

        Returns:
            Optional[str]: The os of this ComputerInfos.
        """
        return self._os

    @os.setter
    def os(self, os: Optional[str]) -> None:
        """
        Sets the os property of this ComputerInfos.
        Args:
            os (Optional[str]): The os of this ComputerInfos.
        """

        self._os: Optional[str] = os

    @property
    def signing(self) -> Optional[bool]:
        """
        Gets the signing of this ComputerInfos.

        Returns:
            Optional[bool]: The signing of this ComputerInfos.
        """
        return self._signing

    @signing.setter
    def signing(self, signing: Optional[bool]) -> None:
        """
        Sets the signing of this ComputerInfos.

        Args:
            signing (Optional[bool]): The signing of this ComputerInfos.
        """

        self._signing = signing

    @property
    def smbv1(self) -> Optional[bool]:
        """
        Gets the smbv1 of this ComputerInfos.

        Returns:
            Optional[bool]: The smbv1 of this ComputerInfos.
        """
        return self._smbv1

    @smbv1.setter
    def smbv1(self, smbv1: Optional[bool]) -> None:
        """
        Sets the smbv1 of this ComputerInfos.

        Args:
            smbv1 (Optional[bool]): The smbv1 of this ComputerInfos.
        """

        self._smbv1 = smbv1

    @property
    def is_dc(self) -> Optional[bool]:
        """
        Gets the is_dc of this ComputerInfos.

        Returns:
            Optional[bool]: The is_dc of this ComputerInfos.
        """
        if self._is_dc is None:
            return False
        return self._is_dc

    @is_dc.setter
    def is_dc(self, is_dc: Optional[bool]) -> None:
        """
        Sets the is_dc of this ComputerInfos.

        Args:
            is_dc (Optional[bool]): The is_dc of this ComputerInfos.
        """

        self._is_dc = is_dc

    @property
    def is_sqlserver(self) -> Optional[bool]:
        """
        Gets the is_sqlserver of this ComputerInfos.

        Returns:
            Optional[bool]: The is_sqlserver of this ComputerInfos.
        """
        if self._is_sqlserver is None:
            return False
        
        return self._is_sqlserver

    @is_sqlserver.setter
    def is_sqlserver(self, is_sqlserver: Optional[bool]):
        """
        Sets the is_sqlserver of this ComputerInfos.

        Args:
            is_sqlserver (Optional[bool]): The is_sqlserver of this ComputerInfos.
        """

        self._is_sqlserver = is_sqlserver

    @property
    def secrets(self) -> List[str]:
        """
        Gets the secrets of this ComputerInfos.

        Returns:
            List[str]: The secrets of this ComputerInfos.
        """
        return self._secrets

    @secrets.setter
    def secrets(self, secrets: List[str]) -> None:
        """
        Sets the secrets of this ComputerInfos.

        Args:
            secrets (List[str]): The secrets of this ComputerInfos.
        """

        self._secrets = secrets
