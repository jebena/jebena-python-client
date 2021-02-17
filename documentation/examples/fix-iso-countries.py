
# This is an example of querying against a DB snapshot and firing off GQL mutations.
# We do not expect batch updates to be done this way normally. However, in certain cases
# it may be easier to modify data by accessing it via SQL and then firing off GQL mutations.
# (We do not support modifications via SQL so as to correctly enforce permissions and maintain
# proper audit logs, among other reasons.)


import json
import sys
import time

import jebena.db.models as models
import jebena.lib.geospatial
from jebena.db.connection import unattributed_person_session_scope

from jebenaclient import run_query

# Open a read-only connection to a postgres server -- this could easily be replaced
# with whatever source of data you're working with (BI tool; .csv export; etc.)
with unattributed_person_session_scope(read_only_connection=True) as session:
    observations_query = session.query(models.Observation) \
        .filter(models.Observation.active_geolocation_point_json != None)

    # Loop through each observation, calculating the country code with our newer function,
    # and firing off a mutation if the country code has changed:
    for observation_obj in observations_query:
        existing_country_code = observation_obj.active_geolocation_iso_3166_a2_code
        new_country_code = jebena.lib.geospatial.get_nearest_country_as_iso_3166_a2_code(
            latitude=observation_obj.active_geolocation_point_json["lat"],
            longitude=observation_obj.active_geolocation_point_json["lon"],
            cache_data_files_in_memory=True
        )
        if existing_country_code == new_country_code:
            continue
        if observation_obj.active_geolocation_iso_3166_a2_code != \
                observation_obj.geolocation_original_iso_3166_a2_code:
            continue

        # This is less than elegant, but gets the job done -- we don't yet have a None token on the GQL api:
        elevation_string = ""
        if "alt" in observation_obj.active_geolocation_point_json and observation_obj.active_geolocation_point_json["alt"] is not None:
            elevation_string = "elevationInMeters: %s" % observation_obj.active_geolocation_point_json["alt"]
        accuracy_string = ""
        if "accuracy" in observation_obj.active_geolocation_point_json and observation_obj.active_geolocation_point_json["accuracy"] is not None:
            accuracy_string = "accuracyInMeters: %s" % observation_obj.active_geolocation_point_json["accuracy"]

        the_query = """mutation  {
  proposeAndAcceptObservationGeolocationOverride(
    observationId: "%s",
    comment: "Updated country code per newer country geodata",
    countryCode: "%s",
    geolocationPoint: {latitude: %s, longitude:%s, %s, %s},
    setCountryCodeToNull: false,
    setGeolocationPointToNull: false
  ) {
    geolocationOriginalIso3166A2Code
    activeGeolocationIso3166A2Code
  }
}
""" % (observation_obj.uuid,
       new_country_code,
       observation_obj.active_geolocation_point_json["lat"],
       observation_obj.active_geolocation_point_json["lon"],
       elevation_string,
       accuracy_string
       )

        print("-"*100)
        print(the_query)
        print(run_query(the_query))
        time.sleep(1)  # Use a slight delay to prevent hitting rate-limits
