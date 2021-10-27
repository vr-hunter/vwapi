from typing import Dict
import json
import aiohttp
from bs4 import BeautifulSoup
from yarl import URL
import time

from .constants import *


class UnauthorizedError(Exception):
    pass


class VWSession:

    def __init__(self, email, password):
        """
        Initialize a session with the VW API. Requires username and password of the VW ID.
        :param email: VW ID email address (user name)
        :param password: VW ID Password
        """
        self.session = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar())
        self.email = email
        self.password = password
        self.global_config = None
        self.token_timestamp = 0
        self.tokens = {}

    def clear(self):
        """
        Clears the current sessions cookies
        :return: None
        """
        self.session.cookie_jar.clear()

    async def log_in(self):
        """
        Log in using the VW ID. Raises an exception on error
        :return: None
        """
        # Clear previous cookies
        self.clear()
        # Start Session
        r = await self.session.get(LOGIN_URL, timeout=HTTP_TIMEOUT)
        if r.status != 200:
            raise UnauthorizedError(f"Unexpected return code {r.status}")
        soup = BeautifulSoup(await r.text(), 'html.parser')
        csrf = soup.find(id="csrf").attrs.get("value")
        relay_state = soup.find(id="input_relayState").attrs.get("value")
        hmac = soup.find(id="hmac").attrs.get("value")
        next_url = soup.find(id="emailPasswordForm").attrs.get("action")

        # Enter email
        params = {"_csrf": csrf, "relayState": relay_state, "hmac": hmac, "email": self.email}
        r = await self.session.post(VW_IDENTITY_HOST + next_url, params=params, timeout=HTTP_TIMEOUT)
        if r.status != 200:
            raise UnauthorizedError(f"Unexpected return code {r.status}")
        soup = BeautifulSoup(await r.text(), 'html.parser')
        csrf = soup.find(id="csrf").attrs.get("value")
        relay_state = soup.find(id="input_relayState").attrs.get("value")
        hmac = soup.find(id="hmac").attrs.get("value")
        next_url = soup.find(id="credentialsForm").attrs.get("action")

        # Enter password
        params = {"_csrf": csrf, "relayState": relay_state, "hmac": hmac, "email": self.email, "password": self.password}
        r = await self.session.post(VW_IDENTITY_HOST + next_url, params=params, timeout=HTTP_TIMEOUT, max_redirects=50)
        if r.status != 200:
            raise UnauthorizedError(f"Unexpected return code {r.status}")

        # get global config
        r = await self.session.get(VW_GLOBAL_CONFIG_URL, timeout=HTTP_TIMEOUT)
        self.global_config = json.loads(await r.text())

    async def _get_tokens(self):
        """
        Gets the bearer tokens and stores them internally. Should not be called directly. Call check_tokens() instead
        :return: None
        """
        # Refresh session by loading the lounge
        await self.session.get(LOUNGE_URL, timeout=HTTP_TIMEOUT)
        # Get Bearer Token
        csrf = self.session.cookie_jar.filter_cookies(URL(VW_HOST)).get("csrf_token").value
        # used to be: csrf = s.cookies.get("csrf_token")
        headers = {"X-CSRF-TOKEN": csrf}
        r = await self.session.get(TOKEN_URL, headers=headers, timeout=HTTP_TIMEOUT)
        if r.status != 200:
            raise UnauthorizedError(f"Unexpected return code {r.status}")
        self.token_timestamp = time.time()
        self.tokens = json.loads(await r.text())

    async def check_tokens(self):
        """
        Checks the validity of the stored tokens and gets new tokens if necessary
        :return: None
        """
        if time.time() - self.token_timestamp > TOKEN_VALIDITY_S:
            await self._get_tokens()

    async def get_cars(self) -> Dict:
        """
        Get information about the cars from the API. Queries the "relations" and "lounge" APIs
        :return: Dict {"relations": <output of relations API>, "lounge": <output of the lounge API>}
        """
        await self.check_tokens()
        # Get lounge data
        headers = {"Authorization": "Bearer " + self.tokens.get("access_token")}
        lounge_request = await self.session.get(LOUNGE_CARS_URL, headers=headers, timeout=HTTP_TIMEOUT)
        if lounge_request.status != 200:
            raise UnauthorizedError(f"Unexpected return code from lounge API:  {lounge_request.status}")

        # Get relations data
        headers["traceId"] = "1915c3f8-614d-4c4b-a6ac-a05fc52608a8"
        relations_request = await self.session.get(RELATIONS_URL_V2, headers=headers, timeout=HTTP_TIMEOUT)
        if relations_request.status != 200:
            print(relations_request.content)
            raise UnauthorizedError(f"Unexpected return code from Relations API: {relations_request.status}")

        return {
            "lounge": json.loads(await lounge_request.text()),
            "relations": json.loads(await relations_request.text()).get("relations")
        }

    async def get_comm_id_by_comm_nr(self, comm_nr: str) -> str:
        """
        Get the Commissioning ID from a Commissioning Number
        :param comm_nr: Commissioning number e.g. ABC123
        :return: Commissioning ID e.g. ABC123-184.2021
        """
        try:
            valid_bids = self.global_config["spaAsyncConfig"]["serviceConfigs"]["myvw_group-vehicle-file"]["customConfig"]["validBids"]
        except KeyError:
            raise ValueError("Couldn't load list of valid BIDs")

        await self.check_tokens()
        headers = {"Authorization": "Bearer " + self.tokens.get("access_token")}
        for year in BID_SEARCH_YEARS:
            for bid in valid_bids:
                r = await self.session.get(VEHICLE_DATA_PATH + bid + str(year) + comm_nr, headers=headers, timeout=HTTP_TIMEOUT)
                if r.status == 200:
                    return f"{comm_nr}-{bid}-{year}"

        raise ValueError("Couldn't find CommID")

    async def add_relation_by_comm_id(self, comm_id: str):
        """
        Add a vehicle to the current VW ID by commissioning ID. Raises an exception on error.
        :param comm_id: Commissioning ID e.g. ABC123-184-2021
        :return: None
        """
        await self.check_tokens()
        headers = {"Authorization": "Bearer " + self.tokens.get("access_token"),
                   "traceId": "1915c3f8-614d-4c4b-a6ac-a05fc52608a8",
                   "Content-Type": "application/json"}
        payload = {"vehicleNickname": comm_id, "vehicle": {"commissionId": comm_id}}

        add_request = await self.session.post(RELATIONS_URL_V1, data=json.dumps(payload), headers=headers, timeout=HTTP_TIMEOUT)
        if add_request.status != 201:
            raise UnauthorizedError(f"Couldn't add car ({add_request.status}): {await add_request.text()}")

    async def remove_relation_by_comm_id(self, comm_id: str):
        """
        Remove a vehicle from the current VW ID by commissioning ID. Raises an exception on error.
        :param comm_id: Commissioning ID e.g. ABC123-184-2021
        :return: None
        """
        await self.check_tokens()
        headers = {"Authorization": "Bearer " + self.tokens.get("access_token"),
                   "traceId": "1915c3f8-614d-4c4b-a6ac-a05fc52608a8",
                   "Content-Type": "application/json"}

        rem_request = await self.session.delete(f"{MY_VEHICLES_URL}?commissionId={comm_id}", headers=headers,
                                              timeout=HTTP_TIMEOUT)
        if not rem_request.ok:
            raise ValueError(f"API returned ({rem_request.status}): {await rem_request.text()}")
