import logging
import typing
from typing import Dict
import json
import aiohttp
from bs4 import BeautifulSoup
from yarl import URL
import time
import re

from http.cookies import SimpleCookie
from email.utils import parsedate
from datetime import datetime

from .constants import *


class UnauthorizedError(Exception):
    pass


class SessionError(Exception):
    pass


class VWSession:

    def __init__(self, email, password):
        """
        Initialize a session with the VW API. Requires username and password of the VW ID.
        :param email: VW ID email address (user name)
        :param password: VW ID Password
        """
        self.session: typing.Optional[aiohttp.ClientSession] = None
        self.email = email
        self.password = password
        self.global_config = None
        self.token_timestamp = 0
        self.tokens = {}
        self.logged_in = False
        self.header = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0'}


    def clear(self):
        """
        Clears the current sessions cookies
        :return: None
        """
        if self.session is None:
            raise SessionError("No active session")

        if self.session is not None:
            self.session.cookie_jar.clear()

    async def log_out(self):
        if self.session is None:
            raise SessionError("No active session")
        if not self.logged_in:
            raise SessionError("Not logged in")

        csrf = self.session.cookie_jar.filter_cookies(URL(VW_HOST)).get("csrf_token").value
        r = await self.session.get(f"{LOGOUT_URL}?_csrf={csrf}", timeout=HTTP_TIMEOUT, headers=self.header)
        r.close()
        self.logged_in = False

    @staticmethod
    async def rewrite_cookies(session: aiohttp.ClientSession, trace_config_ctx, params: aiohttp.TraceRequestEndParams):
        cookies = [v for x, v in params.response.headers.items() if x.lower() == "set-cookie"]
        for cookie in cookies:
            cookie_params = cookie.split(";")
            changed = False

            for i, v in enumerate(cookie_params):
                if v.strip().lower().startswith("expires") and not v.strip().endswith("GMT"):
                    logging.debug("Found non-compliant cookie expiration datetime")
                    try:
                        key, value = tuple(v.split("="))
                        parsed_rfc2822_date = parsedate(value.strip())
                        date_rfc1123 = datetime.fromtimestamp(time.mktime(parsed_rfc2822_date)).strftime('%a, %d %b %Y %H:%M:%S GMT')
                        cookie_params[i] = key + "=" + date_rfc1123
                        changed = True
                    except Exception as e:
                        logging.error(f"Error while trying to rewrite cookie: {e}")

            if changed:
                reassembled_cookie_str = ";".join(cookie_params)
                session.cookie_jar.update_cookies(SimpleCookie(reassembled_cookie_str), params.url)
                logging.debug("Cookie rewritten")

    async def log_in(self):
        """
        Log in using the VW ID. Raises an exception on error
        :return: None
        """
        if self.logged_in:
            try:
                await self.log_out()
            except Exception as e:
                # Don't let an unsuccessful logout block our login attempt
                logging.warning(f"Couldn't log-out during log-in: {repr(e)}")
                self.logged_in = False

        # Clear client session
        if self.session is not None:
            await self.session.close()
            self.session = None

        trace_config = aiohttp.TraceConfig()
        trace_config.on_request_end.append(self.rewrite_cookies)
        trace_config.on_request_redirect.append(self.rewrite_cookies)

        self.session = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(), skip_auto_headers=["User-Agent"], trace_configs=[trace_config])

        # Start VW Session
        async with self.session.get(LOGIN_URL, timeout=HTTP_TIMEOUT, headers=self.header) as r:
            if r.status != 200:
                raise UnauthorizedError(f"Unexpected return code {r.status}")

            soup = BeautifulSoup(await r.text(), 'html.parser')

        csrf = soup.find(id="csrf").attrs.get("value")
        relay_state = soup.find(id="input_relayState").attrs.get("value")
        hmac = soup.find(id="hmac").attrs.get("value")
        next_url = soup.find(id="emailPasswordForm").attrs.get("action")

        # Enter email
        params = {"_csrf": csrf, "relayState": relay_state, "hmac": hmac, "email": self.email}
        async with self.session.post(VW_IDENTITY_HOST + next_url, params=params, timeout=HTTP_TIMEOUT, headers=self.header) as r:
            if r.status != 200:
                raise UnauthorizedError(f"Unexpected return code {r.status}")
            soup = BeautifulSoup(await r.text(), 'html.parser')

        script_field = soup.select_one('script:-soup-contains("templateModel:")').string

        templateModel = json.loads(re.search(r"templateModel\s*:\s*({.*})\s*,\s*\n",script_field).group(1))
        hmac = templateModel["hmac"]
        relay_state = templateModel["relayState"]
        csrf = re.search(r"csrf_token\s*:\s*[\"\'](.*)[\"\']\s*,?\s*\n", script_field).group(1)
        next_url = f"/signin-service/v1/{templateModel['clientLegalEntityModel']['clientId']}/{templateModel['postAction']}"

        # Enter password
        params = {"_csrf": csrf, "relayState": relay_state, "hmac": hmac, "email": self.email, "password": self.password}

        async with self.session.post(VW_IDENTITY_HOST + next_url, params=params, timeout=HTTP_TIMEOUT, max_redirects=50, headers=self.header) as r:
            if r.status != 200:
                raise UnauthorizedError(f"Unexpected return code {r.status}")

        # get global config
        async with await self.session.get(VW_GLOBAL_CONFIG_URL, timeout=HTTP_TIMEOUT, headers=self.header) as r:
            self.global_config = json.loads(await r.text())

        self.logged_in = True

    async def _get_tokens(self):
        """
        Gets the bearer tokens and stores them internally. Should not be called directly. Call check_tokens() instead
        :return: None
        """
        # Refresh session by loading the lounge
        r = await self.session.get(LOUNGE_URL, timeout=HTTP_TIMEOUT, headers=self.header)
        r.close()

        # Get Bearer Token
        csrf = self.session.cookie_jar.filter_cookies(URL(VW_HOST)).get("csrf_token").value
        # used to be: csrf = s.cookies.get("csrf_token")
        headers = {"X-CSRF-TOKEN": csrf}
        async with self.session.get(TOKEN_URL, headers={**headers, **self.header}, timeout=HTTP_TIMEOUT) as r:
            if r.status != 200:
                raise UnauthorizedError(f"Unexpected return code {r.status}")
            self.token_timestamp = time.time()
            self.tokens = json.loads(await r.text())

    async def check_session(self):
        """
        Checks the validity of the stored tokens and gets new tokens if necessary
        :return: None
        """
        if self.session is None:
            raise SessionError("No active session")
        if not self.logged_in:
            raise SessionError("Not logged in")

        if time.time() - self.token_timestamp > TOKEN_VALIDITY_S:
            await self._get_tokens()

    async def get_cars(self) -> Dict:
        """
        Get information about the cars from the API. Queries the "relations" and "lounge" APIs
        :return: Dict {"relations": <output of relations API>, "lounge": <output of the lounge API>}
        """
        await self.check_session()
        # Get lounge data
        headers = {"Authorization": "Bearer " + self.tokens.get("access_token")}
        async with self.session.get(LOUNGE_CARS_URL, headers={**headers, **self.header}, timeout=HTTP_TIMEOUT) as lounge_request:
            if lounge_request.status != 200:
                raise UnauthorizedError(f"Unexpected return code from lounge API:  {lounge_request.status}")
            lounge_request_text = await lounge_request.text()

        # Get relations data
        headers["traceId"] = "1915c3f8-614d-4c4b-a6ac-a05fc52608a8"
        async with self.session.get(RELATIONS_URL_V2, headers={**headers, **self.header}, timeout=HTTP_TIMEOUT) as relations_request:
            if relations_request.status != 200:

                raise UnauthorizedError(f"Unexpected return code from Relations API: {relations_request.status}")
            relations_request_text = await relations_request.text()

        return {
            "lounge": json.loads(lounge_request_text),
            "relations": json.loads(relations_request_text).get("relations")
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

        await self.check_session()
        headers = {"Authorization": "Bearer " + self.tokens.get("access_token")}
        for year in BID_SEARCH_YEARS:
            for bid in valid_bids:
                async with self.session.get(VEHICLE_DATA_PATH + bid + str(year) + comm_nr, headers={**headers, **self.header}, timeout=HTTP_TIMEOUT) as r:
                    if r.status == 200:
                        return f"{comm_nr}-{bid}-{year}"
        raise ValueError("Couldn't find CommID")

    async def add_relation_by_comm_id(self, comm_id: str):
        """
        Add a vehicle to the current VW ID by commissioning ID. Raises an exception on error.
        :param comm_id: Commissioning ID e.g. ABC123-184-2021
        :return: None
        """
        await self.check_session()
        headers = {"Authorization": "Bearer " + self.tokens.get("access_token"),
                   "traceId": "1915c3f8-614d-4c4b-a6ac-a05fc52608a8",
                   "Content-Type": "application/json"}
        payload = {"vehicleNickname": comm_id, "vehicle": {"commissionId": comm_id}}

        async with self.session.post(RELATIONS_URL_V1, data=json.dumps(payload), headers={**headers, **self.header}, timeout=HTTP_TIMEOUT) as add_request:
            if add_request.status != 201:
                raise UnauthorizedError(f"Couldn't add car ({add_request.status}): {await add_request.text()}")

    async def remove_relation_by_comm_id(self, comm_id: str):
        """
        Remove a vehicle from the current VW ID by commissioning ID. Raises an exception on error.
        :param comm_id: Commissioning ID e.g. ABC123-184-2021
        :return: None
        """
        await self.check_session()
        headers = {"Authorization": "Bearer " + self.tokens.get("access_token"),
                   "traceId": "1915c3f8-614d-4c4b-a6ac-a05fc52608a8",
                   "Content-Type": "application/json"}

        async with self.session.delete(f"{MY_VEHICLES_URL}?commissionId={comm_id}", headers={**headers, **self.header}, timeout=HTTP_TIMEOUT) as rem_request:
            if not rem_request.ok:
                raise ValueError(f"API returned ({rem_request.status}): {await rem_request.text()}")
