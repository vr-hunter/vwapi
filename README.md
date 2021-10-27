# VW API Package
This is a simple python3 package can log into a VW ID and query several VW 
APIs.

It uses asyncio and aiohttp for http connections.

Currently, the functionality is limited to 
- Logging in to the VW ID
- Adding / removing vehicles to / from the VW ID
- Querying the "relations" and "lounge" APIs. The former returns 
information on vehicles associated with the VW ID, the latter returns the production 
status of newly purchased vehicles

## Example Usage

    import vwapi
    
    async def main(session: vwapi.VWSession):
        session = vwapi.VWSession("my_vw_id@gmail.com", "my_vw_id_password")
        await session.log_in()
        cars = await session.get_cars()
        print(cars)

    if __name__ == "__main__":
        asyncio.run(main())
