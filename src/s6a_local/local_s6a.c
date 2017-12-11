int
s6a_local_handle_auth_info (
  s6a_auth_info_req_t * air_p)
{
  // STEP 1: A LOT OF AUTH/VALIDATION/PRE-PROCESSING
  // mode: s6a_generate_authentication_info_freq
  DevAssert (air_p);

    // OAILOG_DEBUG (LOG_S6A, "%s plmn: %02X%02X%02X\n", __FUNCTION__, plmn[0], plmn[1], plmn[2]);
    // OAILOG_DEBUG (LOG_S6A, "%s visited_plmn: %02X%02X%02X\n", __FUNCTION__, value.os.data[0], value.os.data[1], value.os.data[2]);

/* INPUT STRUCT:
  imsi: s6a_fd_cnf.dataobj_s6a_user_name
  imsi_length
  visited_plmn: s6a_fd_cnf.dataobj_s6a_visited_plmn_id
  nb_of_vectors: s6a_fd_cnf.dataobj_s6a_number_of_requested_vectors
  IF (re_synchronization) THEN:
  resync_param: s6a_fd_cnf.dataobj_s6a_re_synchronization_info
  NOTE: value.os.data = (air_p->resync_param + RAND_LENGTH_OCTETS);
  */

  // STEP 2: MYSQL COMMANDS
  // model: s6a_auth_info_cb (in the hss)



  // STEP 3: GENERATE THE RESPONSE
  // model: s6a_aia_cb

  /* OUTPUT STRUCT:
    imsi
    imsi_length
    s6a_result_t result: 
      two items, present (a bit) and choice. item choice is UNION of s6a_base_result_t (base) and s6a_experimental_result_t (experimental)
    authentication_info_t auth_info
  */

  // SMS BIG QUESTION: DO WE STILL NEED TO LOOKUP THE QUERY, GIVEN THAT WE'RE NO LONGER
  // USING A TWO-HOST ARCHITECTURE? COULD BE NECESSARY FOR CONTINUITY, THOUGH I DON'T KNOW WHY

  message_p = itti_alloc_new_message (TASK_S6A, S6A_AUTH_INFO_ANS);
  s6a_auth_info_ans_p = &message_p->ittiMsg.s6a_auth_info_ans;
  OAILOG_DEBUG (LOG_S6A, "Received S6A Authentication Information Answer (AIA)\n");

  // IMSI + IMSI LENGTH
  snprintf (s6a_auth_info_ans_p->imsi, (int)hdr->avp_value->os.len + 1,
            "%*s", (int)hdr->avp_value->os.len, hdr->avp_value->os.data);

  // RESULT
  result_code = SMS
  // s6a_fd_cnf.dataobj_s6a_result_code

  if (result_code != NULL) {
    s6a_auth_info_ans_p->result.present = S6A_RESULT_BASE;
    s6a_auth_info_ans_p->result.choice.base = hdr->avp_value->u32;
    MSC_LOG_TX_MESSAGE (MSC_S6A_MME, MSC_NAS_MME, NULL, 0, "0 S6A_AUTH_INFO_ANS imsi %s %s", s6a_auth_info_ans_p->imsi, retcode_2_string (s6a_auth_info_ans_p->result.choice.base));
  } else  {
    // result code is not present, check for experimental result value
    // s6a_fd_cnf.dataobj_s6a_experimental_result
    if (experimental_result) {
      s6a_auth_info_ans_p->result.present = S6A_RESULT_EXPERIMENTAL;
      s6a_parse_experimental_result (avp, &s6a_auth_info_ans_p->result.choice.experimental);
      MSC_LOG_TX_MESSAGE (MSC_S6A_MME, MSC_NAS_MME, NULL, 0, "0 S6A_AUTH_INFO_ANS imsi %s %s", s6a_auth_info_ans_p->imsi, experimental_retcode_2_string (s6a_auth_info_ans_p->result.choice.experimental));
      skip_auth_res = 1
    } else {
      // neither result-code nor experimental result is present, totally wrong behavior.
      MSC_LOG_TX_MESSAGE_FAILED (MSC_S6A_MME, MSC_NAS_MME, NULL, 0, "0 S6A_AUTH_INFO_ANS imsi %s", s6a_auth_info_ans_p->imsi);
      OAILOG_ERROR (LOG_S6A, "Experimental-Result and Result-Code are absent: " "This is not a correct behaviour\n");
      goto err;
    }
  }

  // AUTH_INFO
  if (skip_auth_res == 0) {
    // (fill auth info here)
    auth_info = SMS
    // s6a_fd_cnf.dataobj_s6a_authentication_info
    if (auth_info != NULL) {
      s6a_auth_info_ans_p->auth_info = auth_info;
      // s6a_parse_authentication_info_avp (avp, &s6a_auth_info_ans_p->auth_info)
    } else {
      DevMessage ("We requested E-UTRAN vectors with an immediate response...\n");
      return RETURNerror;
    }
  }

  itti_send_msg_to_task (TASK_NAS_MME, INSTANCE_DEFAULT, message_p);
err:
  return RETURNok;
}

int
s6a_local_hss_handle_auth_info (void) {

  // CHECK 1: IMSI LENGTH
  if (hdr->avp_value->os.len > IMSI_LENGTH_MAX) {
    result_code = ER_DIAMETER_INVALID_AVP_VALUE;
    goto out;
  }

  // STEP 2: Populate MySQL auth info req
  sprintf (auth_info_req.imsi, "%*s", (int)hdr->avp_value->os.len, hdr->avp_value->os.data);
  sscanf (auth_info_req.imsi, "%" SCNu64, &imsi);

  eutran_req_info = SMS
// fd_msg_search_avp (qry, s6a_cnf.dataobj_s6a_req_e_utran_auth_info, &avp)
  if (eutran_req_info) {
    // SHIT-TONS OF IF-ELSE CODE TO PARSE IN A PARENT-CHILD TREE
  } else {

  }

// fd_msg_search_avp (qry, s6a_cnf.dataobj_s6a_visited_plmn_id, &avp)
  visited_plmn_id = SMS
  if (visited_plmn_id) {

  } else {
    result_code = ER_DIAMETER_MISSING_AVP;
    goto out;
  }

  if (hss_mysql_auth_info (&auth_info_req, &auth_info_resp) != 0) {
    /*
     * Database query failed...
     */
    result_code = DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE;
    experimental = 1;
    goto out;
  }

  if (auts != NULL) {
    /*
     * Try to derive SQN_MS from previous RAND
     */
    sqn = sqn_ms_derive (auth_info_resp.opc, auth_info_resp.key, auts, auth_info_resp.rand);

    if (sqn != NULL) {
      /*
       * We succeeded to verify SQN_MS...
       */
      /*
       * Pick a new RAND and store SQN_MS + RAND in the HSS
       */
      generate_random (vector[0].rand, RAND_LENGTH);
      hss_mysql_push_rand_sqn (auth_info_req.imsi, vector[0].rand, sqn);
      hss_mysql_increment_sqn (auth_info_req.imsi);
      free (sqn);
    }

    /*
     * Fetch new user data
     */
    if (hss_mysql_auth_info (&auth_info_req, &auth_info_resp) != 0) {
      /*
       * Database query failed...
       */
      result_code = DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE;
      experimental = 1;
      goto out;
    }

    sqn = auth_info_resp.sqn;
    for (int i = 0; i < num_vectors; i++) {
      generate_random (vector[i].rand, RAND_LENGTH);
      generate_vector (auth_info_resp.opc, imsi, auth_info_resp.key, hdr->avp_value->os.data, sqn, &vector[i]);
    }
    hss_mysql_push_rand_sqn (auth_info_req.imsi, vector[num_vectors-1].rand, sqn);
  } else {
    /*
     * Pick a new RAND and store SQN_MS + RAND in the HSS
     */
    for (int i = 0; i < num_vectors; i++) {
      generate_random (vector[i].rand, RAND_LENGTH);
      sqn = auth_info_resp.sqn;
      /*
       * Generate authentication vector
       */
      generate_vector (auth_info_resp.opc, imsi, auth_info_resp.key, hdr->avp_value->os.data, sqn, &vector[i]);
    }
    hss_mysql_push_rand_sqn (auth_info_req.imsi, vector[num_vectors-1].rand, sqn);
  }

  hss_mysql_increment_sqn (auth_info_req.imsi);

  // SMS: THE REST OF THE CODE SIMPLY COMPILES VALUES AND SENDS THEM OUT OVER THE WIRE

int result_code
int experimental

local_s6a_add_result_code() does some logic/processing of result 
}


int
local_s6a_add_result_code (
  s6a_auth_info_ans_t *response,
  int result_code,
  int experimental)
{
  struct avp                             *avp;
  union avp_value                         value;

  if (DIAMETER_ERROR_IS_VENDOR (result_code) && experimental != 0) {
    struct avp                             *experimental_result;

    CHECK_FCT (fd_msg_avp_new (s6a_cnf.dataobj_s6a_experimental_result, 0, &experimental_result));
    CHECK_FCT (fd_msg_avp_new (s6a_cnf.dataobj_s6a_vendor_id, 0, &avp));
    value.u32 = VENDOR_3GPP;
    CHECK_FCT (fd_msg_avp_setvalue (avp, &value));
    CHECK_FCT (fd_msg_avp_add (experimental_result, MSG_BRW_LAST_CHILD, avp));
    CHECK_FCT (fd_msg_avp_new (s6a_cnf.dataobj_s6a_experimental_result_code, 0, &avp));
    value.u32 = result_code;
    CHECK_FCT (fd_msg_avp_setvalue (avp, &value));
    CHECK_FCT (fd_msg_avp_add (experimental_result, MSG_BRW_LAST_CHILD, avp));
    CHECK_FCT (fd_msg_avp_add (ans, MSG_BRW_LAST_CHILD, experimental_result));
    /*
     * Add Origin_Host & Origin_Realm AVPs
     */
    CHECK_FCT (fd_msg_add_origin (ans, 0));
  } else {
    /*
     * This is a code defined in the base protocol: result-code AVP should
     * * * * be used.
     */
    CHECK_FCT (fd_msg_rescode_set (ans, retcode_2_string (result_code), NULL, failed_avp, 1));
    response.result.choice.base = 
  }

  return 0;
}