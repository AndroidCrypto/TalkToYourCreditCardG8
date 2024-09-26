package de.androidcrypto.talktoyourcreditcard;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.media.MediaPlayer;
import android.net.Uri;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Log;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.webkit.WebView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import com.github.devnied.emvnfccard.utils.TlvUtil;
import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlv;
import com.payneteasy.tlv.BerTlvParser;
import com.payneteasy.tlv.BerTlvs;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;

import mehdi.sakout.aboutpage.AboutPage;
import mehdi.sakout.aboutpage.Element;

public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    private final String TAG = "MainAct";
    private com.google.android.material.textfield.TextInputEditText etData, etLog;
    private View loadingLayout;
    private NfcAdapter mNfcAdapter;

    private String outputString = ""; // used for the UI output
    private String exportString = ""; // used for exporting the log to a text file
    private String exportStringFileName = "emv.html";
    private final String stepSeparatorString = "*********************************";
    private final String lineSeparatorString = "---------------------------------";
    Context context;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        etData = findViewById(R.id.etData);
        etLog = findViewById(R.id.etLog);
        loadingLayout = findViewById(R.id.loading_layout);

        context = getApplicationContext();

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
    }

    /**
     * section for NFC
     */

    /**
     * This method is run in another thread when a card is discovered
     * This method cannot direct interact with the UI Thread
     * Use `runOnUiThread` method to change the UI from this method
     *
     * @param tag discovered tag
     */

    @Override
    public void onTagDiscovered(Tag tag) {
        clearData();
        Log.d(TAG, "NFC tag discovered");
        writeToUiAppend("NFC tag discovered");
        playSinglePing();
        setLoadingLayoutVisibility(true);
        byte[] tagId = tag.getId();
        writeToUiAppend("TagId: " + bytesToHexNpe(tagId));
        String[] techList = tag.getTechList();
        writeToUiAppend("TechList found with these entries:");
        boolean isoDepInTechList = false;
        for (String s : techList) {
            writeToUiAppend(s);
            if (s.equals("android.nfc.tech.IsoDep")) isoDepInTechList = true;
        }
        // proceed only if tag has IsoDep in the techList
        if (isoDepInTechList) {
            IsoDep nfc = null;
            nfc = IsoDep.get(tag);
            if (nfc != null) {
                try {
                    nfc.connect();
                    Log.d(TAG, "connection with card success");
                    writeToUiAppend("connection with card success");
                    // here we are going to start our journey through the card

                    printStepHeader(0, "our journey begins");
                    writeToUiAppend(etData, "00 reading of the card started");

                    writeToUiAppend("increase IsoDep timeout for long lasting reading");
                    writeToUiAppend("timeout old: " + nfc.getTimeout() + " ms");
                    nfc.setTimeout(10000);
                    writeToUiAppend("timeout new: " + nfc.getTimeout() + " ms");


                    /**
                     * step 1 code start
                     */

                    printStepHeader(1, "select PPSE");
                    byte[] PPSE = "2PAY.SYS.DDF01".getBytes(StandardCharsets.UTF_8); // PPSE
                    byte[] selectPpseCommand = selectApdu(PPSE);
                    byte[] selectPpseResponse = nfc.transceive(selectPpseCommand);
                    writeToUiAppend("01 select PPSE command  length " + selectPpseCommand.length + " data: " + bytesToHexNpe(selectPpseCommand));
                    writeToUiAppend("01 select PPSE response length " + selectPpseResponse.length + " data: " + bytesToHexNpe(selectPpseResponse));
                    writeToUiAppend(etData, "01 select PPSE completed");
                    writeToUiAppend(prettyPrintDataToString(selectPpseResponse));

                    byte[] selectPpseResponseOk = checkResponse(selectPpseResponse);
                    // proceed only when te do have a positive read result = 0x'9000' at the end of response data
                    if (selectPpseResponseOk != null) {

                        /**
                         * step 2 code start
                         */

                        //writeToUiAppend("");
                        printStepHeader(2, "search applications on card");
                        writeToUiAppend("02 analyze select PPSE response and search for tag 0x4F (applications on card)");

                        BerTlvParser parser = new BerTlvParser();
                        BerTlvs tlv4Fs = parser.parse(selectPpseResponseOk);
                        // find all entries for tag 0x4f
                        List<BerTlv> tag4fList = tlv4Fs.findAll(new BerTag(0x4F));
                        if (tag4fList.size() < 1) {
                            writeToUiAppend("there is no tag 0x4F available, stopping here");
                            startEndSequence(nfc);
                        }
                        writeToUiAppend("Found tag 0x4F " + tag4fList.size() + (tag4fList.size() == 1 ? " time:" : " times:"));
                        ArrayList<byte[]> aidList = new ArrayList<>();
                        for (int i4f = 0; i4f < tag4fList.size(); i4f++) {
                            BerTlv tlv4f = tag4fList.get(i4f);
                            byte[] tlv4fBytes = tlv4f.getBytesValue();
                            aidList.add(tlv4fBytes);
                            writeToUiAppend("application Id (AID): " + bytesToHexNpe(tlv4fBytes));
                        }
                        writeToUiAppend(etData, "02 analyze select PPSE response completed");

                        /**
                         * step 2 code end
                         */

                        /**
                         * step 3 code start
                         */

                        // step 03: iterating through aidList by selecting AID
                        for (int aidNumber = 0; aidNumber < tag4fList.size(); aidNumber++) {
                            byte[] aidSelected = aidList.get(aidNumber);
                            writeToUiAppend("");
                            printStepHeader(3, "select application by AID");
                            writeToUiAppend("03 select application by AID " + bytesToHexNpe(aidSelected) + " (number " + (aidNumber + 1) + ")");
                            byte[] selectAidCommand = selectApdu(aidSelected);
                            byte[] selectAidResponse = nfc.transceive(selectAidCommand);
                            writeToUiAppend("");
                            writeToUiAppend("03 select AID command  length " + selectAidCommand.length + " data: " + bytesToHexNpe(selectAidCommand));
                            writeToUiAppend("03 select AID response length " + selectAidResponse.length + " data: " + bytesToHexNpe(selectAidResponse));
                            writeToUiAppend(prettyPrintDataToString(selectAidResponse));
                            writeToUiAppend(etData, "03 select AID completed");

                            /**
                             * step 4 code start
                             */

                            byte[] selectAidResponseOk = checkResponse(selectAidResponse);
                            if (selectAidResponseOk != null) {
                                //writeToUiAppend("");
                                printStepHeader(4, "search for tag 0x9F38");
                                writeToUiAppend("04 search for tag 0x9F38 in the selectAid response");
                                /**
                                 * note: different behaviour between VisaCard, Mastercard and German GiroCards
                                 * Mastercard has NO PDOL, Visa gives PDOL in tag 9F38
                                 * next step: search for tag 9F38 Processing Options Data Object List (PDOL)
                                 */

                                /*
                                Caught a RuntimeException from the binder stub implementation.
                                java.lang.IllegalStateException: At position 1 the len is more then 3 [36]
	                            at com.payneteasy.tlv.BerTlvParser.getDataLength(BerTlvParser.java:205)
	                            That can happe when invalid are used to get parsed.
                                 */
                                System.out.println("selectAidResponseOk: " + bytesToHexNpe(selectAidResponseOk));
                                BerTlv tag9f38;
                                try {
                                    BerTlvs tlvsAid = parser.parse(selectAidResponseOk);
                                    tag9f38 = tlvsAid.find(new BerTag(0x9F, 0x38));
                                    writeToUiAppend(etData, "04 search for tag 0x9F38 in the selectAid response completed");
                                } catch (IllegalStateException e) {
                                    tag9f38 = null;
                                    Log.e(TAG, "Parsing invalid data: " + e.getMessage());
                                }
                                byte[] gpoRequestCommand;

                                // comment this out for regular workflow
                                DolValues dolValues = new DolValues();
                                writeToUiAppend("Available predefined values for PDOL and CDOL");
                                writeToUiAppend(dolValues.dump());

                                if (tag9f38 != null) {
                                    /**
                                     * the following code is for VisaCards and (German) GiroCards as we found a PDOL
                                     */
                                    writeToUiAppend("");
                                    writeToUiAppend("### processing the American Express, VisaCard and GiroCard path ###");
                                    writeToUiAppend("");
                                    byte[] pdolValue = tag9f38.getBytesValue();

                                    writeToUiAppend("found tag 0x9F38 (PDOL) in the selectAid with this length: " + pdolValue.length + " data: " + bytesToHexNpe(pdolValue));
                                    byte[][] gpoRequestCommandArray = getGpoFromPdolExtended(pdolValue, new byte[]{(byte) 0x00}); // 00 = default, maximum 03

                                    gpoRequestCommand = gpoRequestCommandArray[0];
                                    String pdolRequestString = new String(gpoRequestCommandArray[1], StandardCharsets.UTF_8);
                                    writeToUiAppend("");
                                    writeToUiAppend(pdolRequestString);
                                } else { // if (tag9f38 != null) {
                                    /**
                                     * MasterCard code
                                     */
                                    writeToUiAppend("");
                                    writeToUiAppend("### processing the MasterCard path ###");
                                    writeToUiAppend("");

                                    writeToUiAppend("No PDOL found in the selectAid response, generating a 'null' PDOL");
                                    //gpoRequestCommand = getGpoFromPdol(new byte[0]); // empty PDOL
                                    byte[][] gpoRequestCommandArray = getGpoFromPdolExtended(new byte[0], new byte[]{(byte) 0x00});
                                    gpoRequestCommand = gpoRequestCommandArray[0];
                                    String pdolRequestString = new String(gpoRequestCommandArray[1], StandardCharsets.UTF_8);
                                    writeToUiAppend("");
                                    writeToUiAppend(pdolRequestString);
                                }

                                //writeToUiAppend("");
                                printStepHeader(5, "get the processing options");
                                writeToUiAppend("05 get the processing options  command length: " + gpoRequestCommand.length + " data: " + bytesToHexNpe(gpoRequestCommand));

                                /**
                                 * step 5 code starts
                                 */

                                /**
                                 * WARNING: each get processing options request increases the icc internal
                                 * 'application transaction counter'. If the 2 byte long counter reaches the
                                 * maximum of '65535' (0xFFFF) the card will no longer accept any read commands
                                 * and the card is irretrievable damaged.
                                 * DO NOT RUN THIS COMMAND IN A LOOP !
                                 */

                                byte[] gpoRequestResponse = nfc.transceive(gpoRequestCommand);
                                byte[] gpoRequestResponseOk;
                                writeToUiAppend(etData, "05 get the processing options completed");
                                if (gpoRequestResponse != null) {
                                    writeToUiAppend("05 get the processing options response length: " + gpoRequestResponse.length + " data: " + bytesToHexNpe(gpoRequestResponse));
                                    gpoRequestResponseOk = checkResponse(gpoRequestResponse);
                                    if (gpoRequestResponseOk != null) {
                                        writeToUiAppend(prettyPrintDataToString(gpoRequestResponse));
                                    }

                                } else {
                                    writeToUiAppend(etData, "05 get the processing options failed");
                                    writeToUiAppend("The command for get processing options failed. It might be a good idea to use an alternate tag 0x9966 Terminal Transaction Qualifiers");
                                    startEndSequence(nfc);
                                    // the app will end here
                                }

                                /**
                                 * step 5 code end
                                 */

                                /**
                                 * step 6 code start
                                 */

                                // parse content of gpoResponse to get Track 2 or AFL

                                /**
                                 * We do have 3 scenarios to work with:
                                 * a) the response contains a Track 2 Equivalent Data tag (tag 0x57)
                                 * b) the response is of type 'Response Message Template Format 1' (tag 0x80)
                                 * c) the response is of type 'Response Message Template Format 2' (tag 0x77)
                                 */
                                BerTlvs tlvsGpo = parser.parse(gpoRequestResponse);
                                byte[] aflBytes = null;

                                /**
                                 * workflow a)
                                 * The response contains a Track 2 Equivalent Data tag and from this we can directly
                                 * retrieve the Primary Application Number (PAN, here the Credit Card Number)
                                 * found using a VisaCard
                                 */

                                BerTlv tag57 = tlvsGpo.find(new BerTag(0x57));
                                if (tag57 != null) {
                                    //writeToUiAppend("");
                                    writeToUiAppend("workflow a)");
                                    writeToUiAppend("");
                                    printStepHeader(6, "read files & search PAN");
                                    writeToUiAppend("06 read the files from card skipped");
                                    writeToUiAppend(etData, "06 read the files from card skipped");

                                    writeToUiAppend("the response contains a Track 2 Equivalent Data tag [tag 0x57]");

                                    /**
                                     * step 7 code start
                                     */

                                    writeToUiAppend("the response contains a Track 2 Equivalent Data tag [tag 0x57]");
                                    byte[] gpoResponseTag57 = tag57.getBytesValue();
                                    writeToUiAppend("found tag 0x57 in the gpoResponse length: " + gpoResponseTag57.length + " data: " + bytesToHexNpe(gpoResponseTag57));
                                    String pan = getPanFromTrack2EquivalentData(gpoResponseTag57);
                                    String expDate = getExpirationDateFromTrack2EquivalentData(gpoResponseTag57);
                                    writeToUiAppend("found a PAN " + pan + " with Expiration date: " + expDate);
                                    writeToUiAppend("");
                                    printStepHeader(7, "print PAN & expire date");
                                    writeToUiAppend("07 get PAN and Expiration date from tag 0x57 (Track 2 Equivalent Data)");
                                    writeToUiAppend(etData, "07 get PAN and Expiration date from tag 0x57 (Track 2 Equivalent Data) completed");
                                    writeToUiAppend("data for AID " + bytesToHexNpe(aidSelected));
                                    writeToUiAppend("PAN: " + pan);
                                    String expirationDateString = "Expiration date (" + (expDate.length() == 4 ? "YYMM): " : "YYMMDD): ") + expDate;
                                    writeToUiAppend(expirationDateString);
                                    writeToUiAppend(etData, "data for AID " + bytesToHexNpe(aidSelected));
                                    writeToUiAppend(etData,"PAN: " + pan);
                                    writeToUiAppend(etData, expirationDateString);
                                    writeToUiAppend("");

                                    /**
                                     * step 7 code end
                                     */

                                }

                                /**
                                 * workflow b)
                                 * The response is of type 'Response Message Template Format 1' and we need to know
                                 * the meaning of each byte, so we need to parse the content to get the data for the
                                 * 'Application File Locator' (AFL).
                                 * found using a American Express Card
                                 */

                                BerTlv tag80 = tlvsGpo.find(new BerTag(0x80));
                                if (tag80 != null) {
                                    //writeToUiAppend("");
                                    writeToUiAppend("workflow b)");
                                    writeToUiAppend("the response is of type 'Response Message Template Format 1' [tag 0x80]");
                                    byte[] gpoResponseTag80 = tag80.getBytesValue();
                                    writeToUiAppend("found tag 0x80 in the gpoResponse length: " + gpoResponseTag80.length + " data: " + bytesToHexNpe(gpoResponseTag80));
                                    aflBytes = Arrays.copyOfRange(gpoResponseTag80, 2, gpoResponseTag80.length);
                                }


                                /**
                                 * workflow c)
                                 * The response is of type 'Response Message Template Format 2' and we need to find
                                 * tag 0x94; the content is the 'Application File Locator' (AFL)
                                 * found using a MasterCard
                                 */

                                BerTlv tag77 = tlvsGpo.find(new BerTag(0x77));
                                if (tag77 != null) {
                                    //writeToUiAppend("");
                                    writeToUiAppend("workflow c)");
                                    writeToUiAppend("the response is of type 'Response Message Template Format 2' [tag 0x77]");
                                    writeToUiAppend("found tag 0x77 in the gpoResponse");
                                }
                                BerTlv tag94 = tlvsGpo.find(new BerTag(0x94));
                                if (tag94 != null) {
                                    writeToUiAppend("found 'AFL' [tag 0x94] in the response of type 'Response Message Template Format 2' [tag 0x77]");
                                    byte[] gpoResponseTag94 = tag94.getBytesValue();
                                    writeToUiAppend("found tag 0x94 in the gpoResponse length: " + gpoResponseTag94.length + " data: " + bytesToHexNpe(gpoResponseTag94));
                                    aflBytes = gpoResponseTag94;
                                }

                                writeToUiAppend("");
                                printStepHeader(6, "read files & search PAN");
                                writeToUiAppend("06 read the files from card and search for PAN & Expiration date");
                                writeToUiAppend(etData, "06 read the files from card and search for PAN & Expiration date");

                                List<byte[]> tag94BytesList = divideArray(aflBytes, 4);
                                int tag94BytesListLength = tag94BytesList.size();
                                //writeToUiAppend(etLog, "tag94Bytes divided into " + tag94BytesListLength + " arrays");
                                writeToUiAppend("");
                                writeToUiAppend("The AFL contains " + tag94BytesListLength + (tag94BytesListLength == 1 ? " entry to read" : " entries to read"));

                                // the AFL is a 4 byte long byte array, so I your aflBytes array is 12 bytes long there are three sets to read.

                                /**
                                 * now we are going to read the specified files from the card. The system is as follows:
                                 * The first byte is the SFI, the second byte the first record to read,
                                 * the third byte is the last record to read and byte 4 gives the number
                                 * of sectors involved in offline authorization.
                                 * Here an example: 10 01 03 00
                                 * SFI:             10
                                 * first record:       01
                                 * last record:           03
                                 * offline:                  00
                                 * means that we are asked to read 3 records (number 1, 2 and 3) from SFI 10
                                 *
                                 * The fourth byte codes the number of records involved in offline data
                                 * authentication starting with the record number coded in the second byte. The
                                 * fourth byte may range from zero to the value of the third byte less the value of
                                 * the second byte plus 1.
                                 */

                                for (int i = 0; i < tag94BytesListLength; i++) {
                                    byte[] tag94BytesListEntry = tag94BytesList.get(i);
                                    byte sfiOrg = tag94BytesListEntry[0];
                                    byte rec1 = tag94BytesListEntry[1];
                                    byte recL = tag94BytesListEntry[2];
                                    byte offl = tag94BytesListEntry[3]; // offline authorization
                                    int sfiNew = (byte) sfiOrg | 0x04; // add 4 = set bit 3
                                    int numberOfRecordsToRead = (byteToInt(recL) - byteToInt(rec1) + 1);
                                    writeToUiAppend("for SFI " + byteToHex(sfiOrg) + " we read " + numberOfRecordsToRead + (numberOfRecordsToRead == 1 ? " record" : " records"));
                                    // read records
                                    byte[] readRecordResponse = new byte[0];
                                    for (int iRecord = (int) rec1; iRecord <= (int) recL; iRecord++) {
                                        byte[] cmd = hexToBytes("00B2000400");
                                        cmd[2] = (byte) (iRecord & 0x0FF);
                                        cmd[3] |= (byte) (sfiNew & 0x0FF);
                                        writeToUiAppend("readRecord  command length: " + cmd.length + " data: " + bytesToHexNpe(cmd));
                                        readRecordResponse = nfc.transceive(cmd);
                                        byte[] readRecordResponseTag5a = null;
                                        byte[] readRecordResponseTag5f24 = null;
                                        if (readRecordResponse != null) {
                                            writeToUiAppend("readRecord response length: " + readRecordResponse.length + " data: " + bytesToHexNpe(readRecordResponse));
                                            writeToUiAppend(prettyPrintDataToString(readRecordResponse));
                                            System.out.println("readRecord response length: " + readRecordResponse.length + " data: " + bytesToHexNpe(readRecordResponse));
                                            System.out.println(prettyPrintDataToString(readRecordResponse));

                                            /**
                                             * step 7 code start
                                             */

                                            // checking for PAN and Expiration Date
                                            try {
                                                BerTlvs tlvsReadRecord = parser.parse(readRecordResponse);
                                                BerTlv tag5a = tlvsReadRecord.find(new BerTag(0x5a));
                                                if (tag5a != null) {
                                                    readRecordResponseTag5a = tag5a.getBytesValue();
                                                    writeToUiAppend("found tag 0x5a in the readRecordResponse length: " + readRecordResponseTag5a.length + " data: " + bytesToHexNpe(readRecordResponseTag5a));
                                                }
                                                BerTlv tag5f24 = tlvsReadRecord.find(new BerTag(0x5f, 0x24));
                                                if (tag5f24 != null) {
                                                    readRecordResponseTag5f24 = tag5f24.getBytesValue();
                                                    writeToUiAppend("found tag 0x5f24 in the readRecordResponse length: " + readRecordResponseTag5f24.length + " data: " + bytesToHexNpe(readRecordResponseTag5f24));
                                                }
                                                if (readRecordResponseTag5a != null) {
                                                    String readRecordPanString = removeTrailingF(bytesToHexNpe(readRecordResponseTag5a));
                                                    String readRecordExpirationDateString = bytesToHexNpe(readRecordResponseTag5f24);
                                                    writeToUiAppend("");
                                                    printStepHeader(7, "print PAN & expire date");
                                                    writeToUiAppend("07 get PAN and Expiration date from tags 0x5a and 0x5f24");
                                                    writeToUiAppend(etData, "07 get PAN and Expiration date from tags 0x5a and 0x5f24 completed");
                                                    writeToUiAppend("data for AID " + bytesToHexNpe(aidSelected));
                                                    writeToUiAppend("PAN: " + readRecordPanString);
                                                    String expirationDateString = "Expiration date (" + (readRecordExpirationDateString.length() == 4 ? "YYMM): " : "YYMMDD): ") + readRecordExpirationDateString;
                                                    writeToUiAppend(expirationDateString);
                                                    writeToUiAppend(etData, "data for AID " + bytesToHexNpe(aidSelected));
                                                    writeToUiAppend(etData,"PAN: " + readRecordPanString);
                                                    writeToUiAppend(etData, expirationDateString);
                                                    writeToUiAppend("");
                                                }
                                            } catch (RuntimeException e) {
                                                System.out.println("Runtime Exception: " + e.getMessage());
                                                //startEndSequence(nfc);
                                            }

                                            /**
                                             * step 7 code end
                                             */

                                        } else {
                                            writeToUiAppend("readRecord response was NULL");
                                        }
                                    }
                                }


                                /**
                                 * step 6 code end
                                 */

                            } else { // if (selectAidResponseOk != null) {
                                writeToUiAppend("the selecting AID command failed");
                            }

                            /**
                             * step 4 code end
                             */

                        } // for (int aidNumber = 0; aidNumber < tag4fList.size(); aidNumber++) {

                        /**
                         * step 3 code end
                         */



                    } else {
                        // if (isoDepInTechList) {
                        writeToUiAppend("The discovered NFC tag does not have an IsoDep interface.");
                    }

                    /**
                     * step 1 code end
                     */

                    printStepHeader(99, "our journey ends");
                    writeToUiAppend(etData, "99 reading of the card completed");
                    vibrate();
                } catch (IOException e) {
                    writeToUiAppend("connection with card failure");
                    writeToUiAppend(e.getMessage());
                    // throw new RuntimeException(e);
                    startEndSequence(nfc);
                    return;
                }
            }
        } else {
            // if (isoDepInTechList) {
            writeToUiAppend("The discovered NFC tag does not have an IsoDep interface.");
        }
        // final cleanup
        playDoublePing();
        writeToUiFinal(etLog);
        setLoadingLayoutVisibility(false);
    }


    /**
     * section for emv reading
     */

    /**
     * step 1 code start
     */

    /**
     * build a select apdu command
     *
     * @param data
     * @return
     */
    private byte[] selectApdu(@NonNull byte[] data) {
        byte[] commandApdu = new byte[6 + data.length];
        commandApdu[0] = (byte) 0x00;  // CLA
        commandApdu[1] = (byte) 0xA4;  // INS
        commandApdu[2] = (byte) 0x04;  // P1
        commandApdu[3] = (byte) 0x00;  // P2
        commandApdu[4] = (byte) (data.length & 0x0FF);       // Lc
        System.arraycopy(data, 0, commandApdu, 5, data.length);
        commandApdu[commandApdu.length - 1] = (byte) 0x00;  // Le
        return commandApdu;
    }

    /**
     * step 1 code end
     */

    /**
     * step 4 code start
     */

    /**
     * construct the getProcessingOptions command using the provided pdol
     * the default ttq is null, but another ttq can used if default ttq gives no result for later sending
     * @param pdol
     * @param alternativeTtq
     * @return a byte[][] array
     * [0] = getProcessingOptions command
     * [1] = text table with requested tags from pdol with length and value
     */
    private byte[][] getGpoFromPdolExtended(@NonNull byte[] pdol, byte[] alternativeTtq) {

        byte[][] result = new byte[2][];
        // get the tags in a list
        List<com.github.devnied.emvnfccard.iso7816emv.TagAndLength> tagAndLength = TlvUtil.parseTagAndLength(pdol);
        int tagAndLengthSize = tagAndLength.size();
        StringBuilder returnString = new StringBuilder();
        returnString.append("The card is requesting " + tagAndLengthSize + (tagAndLengthSize == 1 ? " tag" : " tags")).append(" in the PDOL").append("\n");
        returnString.append("\n");
        returnString.append("Tag  Tag Name                        Length Value").append("\n");
        returnString.append("-----------------------------------------------------").append("\n");
        if (tagAndLengthSize < 1) {
            returnString.append("     no PDOL provided, returning an empty command").append("\n");
            returnString.append("-----------------------------------------------------");
            // there are no pdols in the list
            //Log.e(TAG, "there are no PDOLs in the pdol array, aborted");
            //return null;
            // returning an empty PDOL
            String tagLength2d = "00"; // length value
            String tagLength2dAnd2 = "02"; // length value + 2
            String constructedGpoCommandString = "80A80000" + tagLength2dAnd2 + "83" + tagLength2d + "" + "00";
            result[0] = hexToBytes(constructedGpoCommandString);
            result[1] = returnString.toString().getBytes(StandardCharsets.UTF_8);
            return result;
            //return hexToBytes(constructedGpoCommandString);
        }
        int valueOfTagSum = 0; // total length
        StringBuilder sb = new StringBuilder(); // takes the default values of the tags
        DolValues dolValues = new DolValues();
        for (int i = 0; i < tagAndLengthSize; i++) {
            // get a single tag
            com.github.devnied.emvnfccard.iso7816emv.TagAndLength tal = tagAndLength.get(i); // eg 9f3704
            byte[] tagToSearch = tal.getTag().getTagBytes(); // gives the tag 9f37
            int lengthOfTag = tal.getLength(); // 4
            String nameOfTag = tal.getTag().getName();
            valueOfTagSum += tal.getLength(); // add it to the sum
            // now we are trying to find a default value
            byte[] defaultValue = dolValues.getDolValue(tagToSearch, alternativeTtq);
            byte[] usedValue = new byte[0];
            if (defaultValue != null) {
                if (defaultValue.length > lengthOfTag) {
                    // cut it to correct length
                    usedValue = Arrays.copyOfRange(defaultValue, 0, lengthOfTag);
                    //Log.i(TAG, "asked for tag: " + bytesToHexNpe(tal.getTag().getTagBytes()) + " default is too long, cut to: " + bytesToHexNpe(usedValue));
                } else if (defaultValue.length < lengthOfTag) {
                    // increase length
                    usedValue = new byte[lengthOfTag];
                    System.arraycopy(defaultValue, 0, usedValue, 0, defaultValue.length);
                    //Log.i(TAG, "asked for tag: " + bytesToHexNpe(tal.getTag().getTagBytes()) + " default is too short, increased to: " + bytesToHexNpe(usedValue));
                } else {
                    // correct length
                    usedValue = defaultValue.clone();
                    //Log.i(TAG, "asked for tag: " + bytesToHexNpe(tal.getTag().getTagBytes()) + " default found: " + bytesToHexNpe(usedValue));
                }
            } else {
                // defaultValue is null means the tag was not found in our tags database for default values
                usedValue = new byte[lengthOfTag];
                //Log.i(TAG, "asked for tag: " + bytesToHexNpe(tal.getTag().getTagBytes()) + " NO default found, generate zeroed: " + bytesToHexNpe(usedValue));
            }
            // now usedValue does have the correct length
            sb.append(bytesToHexNpe(usedValue));
            returnString.append(trimStringRight(bytesToHexNpe(tagToSearch),5)).append(trimStringRight(nameOfTag, 36)).append(trimStringRight(String.valueOf(lengthOfTag), 3)).append(bytesToHexBlankNpe(usedValue)).append("\n");
        }
        returnString.append("-----------------------------------------------------").append("\n");
        String constructedGpoString = sb.toString();
        String tagLength2d = bytesToHexNpe(intToByteArray(valueOfTagSum)); // length value
        String tagLength2dAnd2 = bytesToHexNpe(intToByteArray(valueOfTagSum + 2)); // length value + 2
        String constructedGpoCommandString = "80A80000" + tagLength2dAnd2 + "83" + tagLength2d + constructedGpoString + "00";
        result[0] = hexToBytes(constructedGpoCommandString);
        result[1] = returnString.toString().getBytes(StandardCharsets.UTF_8);
        return result;
    }

    /**
     * step 4 code end
     */

    /**
     * step 7 code start
     */

    private String getPanFromTrack2EquivalentData(byte[] track2Data) {
        if (track2Data != null) {
            String track2DataString = bytesToHexNpe(track2Data);
            int posSeparator = track2DataString.toUpperCase().indexOf("D");
            return removeTrailingF(track2DataString.substring(0, posSeparator));
        } else {
            return "";
        }
    }

    private String getExpirationDateFromTrack2EquivalentData(byte[] track2Data) {
        if (track2Data != null) {
            String track2DataString = bytesToHexNpe(track2Data);
            int posSeparator = track2DataString.toUpperCase().indexOf("D");
            return track2DataString.substring((posSeparator + 1), (posSeparator + 5));
        } else {
            return "";
        }
    }

    /**
     * remove all trailing 0xF's trailing in the 16 byte length field tag 0x5a = PAN and in Track2EquivalentData
     * PAN is padded with 'F' if not of length 16
     *
     * @param input
     * @return
     */
    private String removeTrailingF(String input) {
        int index;
        for (index = input.length() - 1; index >= 0; index--) {
            if (input.charAt(index) != 'f') {
                break;
            }
        }
        return input.substring(0, index + 1);
    }

    /**
     * step 7 code end
     */


    /**
     * add blanks to a string on right side up to a length of len
     * if the data.length >= len one character is deleted to get minimum one blank
     *
     * @param data
     * @param len
     * @return
     */
    private String trimStringRight(String data, int len) {
        if (data.length() >= len) {
            data = data.substring(0, (len - 1));
        }
        while (data.length() < len) {
            data = data + " ";
        }
        return data;
    }

    /**
     * checks if the response has an 0x'9000' at the end means success
     * and the method returns the data without 0x'9000' at the end
     * if any other trailing bytes show up the method returns NULL
     *
     * @param data
     * @return
     */
    private byte[] checkResponse(@NonNull byte[] data) {
        // simple sanity check
        if (data.length < 5) {
            return null;
        } // not ok
        int status = ((0xff & data[data.length - 2]) << 8) | (0xff & data[data.length - 1]);
        if (status != 0x9000) {
            return null;
        } else {
            return Arrays.copyOfRange(data, 0, data.length - 2);
        }
    }

    /**
     * section for conversion utils
     */

    /**
     * converts a byte array to a hex encoded string
     * This method is Null Pointer Exception (NPE) safe
     *
     * @param bytes
     * @return hex encoded string
     */
    public static String bytesToHexNpe(byte[] bytes) {
        if (bytes != null) {
            StringBuffer result = new StringBuffer();
            for (byte b : bytes)
                result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
            return result.toString();
        } else {
            return "";
        }
    }

    /**
     * converts a byte array to a hex encoded string
     * This method is Null Pointer Exception (NPE) safe
     *
     * @param bytes
     * @return hex encoded string with a blank after each value
     */
    public static String bytesToHexBlankNpe(byte[] bytes) {
        if (bytes == null) return "";
        StringBuffer result = new StringBuffer();
        for (byte b : bytes)
            result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1)).append(" ");
        return result.toString();
    }

    /**
     * converts a hex encoded string to a byte array
     *
     * @param str
     * @return
     */
    public static byte[] hexToBytes(String str) {
        byte[] bytes = new byte[str.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(str.substring(2 * i, 2 * i + 2),
                    16);
        }
        return bytes;
    }

    /**
     * converts a byte to int
     *
     * @param b
     * @return
     */
    public static int byteToInt(byte b) {
        return (int) b & 0xFF;
    }

    public static int intFromByteArray(byte[] bytes) {
        return new BigInteger(bytes).intValue();
    }

    /**
     * converts a byte to its hex string representation
     *
     * @param data
     * @return
     */
    public static String byteToHex(byte data) {
        int hex = data & 0xFF;
        return Integer.toHexString(hex);
    }

    /**
     * converts an integer to a byte array
     *
     * @param value
     * @return
     */
    public static byte[] intToByteArray(int value) {
        return new BigInteger(String.valueOf(value)).toByteArray();
    }

    /**
     * splits a byte array in chunks
     *
     * @param source
     * @param chunksize
     * @return a List<byte[]> with sets of chunksize
     */
    private static List<byte[]> divideArray(byte[] source, int chunksize) {
        List<byte[]> result = new ArrayList<byte[]>();
        int start = 0;
        while (start < source.length) {
            int end = Math.min(source.length, start + chunksize);
            result.add(Arrays.copyOfRange(source, start, end));
            start += chunksize;
        }
        return result;
    }

    /**
     * section for NFC
     */

    private void showWirelessSettings() {
        Toast.makeText(this, "You need to enable NFC", Toast.LENGTH_SHORT).show();
        Intent intent = new Intent(Settings.ACTION_WIRELESS_SETTINGS);
        startActivity(intent);
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (mNfcAdapter != null) {
            if (!mNfcAdapter.isEnabled())
                showWirelessSettings();
            Bundle options = new Bundle();
            // Work around for some broken Nfc firmware implementations that poll the card too fast
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);
            // Enable ReaderMode for all types of card and disable platform sounds
            // the option NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK is NOT set
            // to get the data of the tag afer reading
            mNfcAdapter.enableReaderMode(this,
                    this,
                    NfcAdapter.FLAG_READER_NFC_A |
                            NfcAdapter.FLAG_READER_NFC_B |
                            NfcAdapter.FLAG_READER_NFC_F |
                            NfcAdapter.FLAG_READER_NFC_V |
                            NfcAdapter.FLAG_READER_NFC_BARCODE |
                            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    options);
        }
    }

    /**
     * important is the disabling of the ReaderMode when activity is pausing
     */

    @Override
    protected void onPause() {
        super.onPause();
        if (mNfcAdapter != null)
            mNfcAdapter.disableReaderMode(this);
    }

    /**
     * section for UI
     */

    /**
     * shows a progress bar as long as the reading lasts
     *
     * @param isVisible
     */

    private void setLoadingLayoutVisibility(boolean isVisible) {
        runOnUiThread(() -> {
            if (isVisible) {
                loadingLayout.setVisibility(View.VISIBLE);
            } else {
                loadingLayout.setVisibility(View.GONE);
            }
        });
    }

    /**
     * vibrate
     */
    private void vibrate() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ((Vibrator) getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(150, 10));
        } else {
            Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
            v.vibrate(200);
        }
    }

    /**
     * Sound files downloaded from Material Design Sounds
     * https://m2.material.io/design/sound/sound-resources.html
     */
    private void playSinglePing() {
        MediaPlayer mp = MediaPlayer.create(this, R.raw.notification_decorative_02);
        mp.start();
    }

    private void playDoublePing() {
        MediaPlayer mp = MediaPlayer.create(this, R.raw.notification_decorative_01);
        mp.start();
    }

    private void startEndSequence(IsoDep nfc) {
        playDoublePing();
        writeToUiFinal(etLog);
        setLoadingLayoutVisibility(false);
        vibrate();
        try {
            nfc.close();
        } catch (IOException e) {
            // throw new RuntimeException(e);
        }
        return;
    }

    /**
     * prints a nice header for each step
     *
     * @param step
     * @param message
     */
    private void printStepHeader(int step, String message) {
        // message should not extend 29 characters, longer messages will get trimmed
        String emptyMessage = "                                 ";
        StringBuilder sb = new StringBuilder();
        sb.append(outputString); // has already a line feed at the end
        sb.append("").append("\n");
        sb.append(stepSeparatorString).append("\n");
        sb.append("************ step ").append(String.format("%02d", step)).append(" ************").append("\n");
        sb.append("* ").append((message + emptyMessage).substring(0, 29)).append(" *").append("\n");
        sb.append(stepSeparatorString).append("\n");
        outputString = sb.toString();
    }

    /**
     * used for printing the card responses in a human readable format to a string
     *
     * @param responseData
     * @return
     */
    private String prettyPrintDataToString(byte[] responseData) {
        StringBuilder sb = new StringBuilder();
        sb.append("------------------------------------").append("\n");
        sb.append(trimLeadingLineFeeds(TlvUtil.prettyPrintAPDUResponse(responseData))).append("\n");
        sb.append("------------------------------------").append("\n");
        return sb.toString();
    }

    /**
     * trim leading line feeds if existing
     *
     * @param input
     * @return
     */
    public static String trimLeadingLineFeeds(String input) {
        String[] output = input.split("^\\n+", 2);
        return output.length > 1 ? output[1] : output[0];
    }

    private void clearData() {
        runOnUiThread(() -> {
            outputString = "";
            exportString = "";
            etData.setText("");
            etLog.setText("");
        });
    }

    private void writeToUiAppend(String message) {
        //System.out.println(message);
        outputString = outputString + message + "\n";
    }

    private void writeToUiAppend(final TextView textView, String message) {
        runOnUiThread(() -> {
            if (TextUtils.isEmpty(textView.getText().toString())) {
                if (textView == (TextView) etLog) {
                } else {
                    textView.setText(message);
                }
            } else {
                String newString = textView.getText().toString() + "\n" + message;
                if (textView == (TextView) etLog) {
                } else {
                    textView.setText(newString);
                }
            }
        });
    }

    private void writeToUiFinal(final TextView textView) {
        if (textView == (TextView) etLog) {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    textView.setText(outputString);
                    System.out.println(outputString); // print the data to console
                }
            });
        }
    }

    private void provideTextViewDataForExport(TextView textView) {
        exportString = textView.getText().toString();
    }

    private void writeToUiToast(String message) {
        runOnUiThread(() -> {
            Toast.makeText(getApplicationContext(),
                    message,
                    Toast.LENGTH_SHORT).show();
        });
    }

    /**
     * section OptionsMenu export text file methods
     */

    private void exportTextFile() {
        provideTextViewDataForExport(etLog);
        if (exportString.isEmpty()) {
            writeToUiToast("Scan a tag first before writing files :-)");
            return;
        }
        writeStringToExternalSharedStorage();
    }

    private void writeStringToExternalSharedStorage() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        // Optionally, specify a URI for the file that should appear in the
        // system file picker when it loads.
        // boolean pickerInitialUri = false;
        // intent.putExtra(DocumentsContract.EXTRA_INITIAL_URI, pickerInitialUri);
        // get filename from edittext
        String filename = exportStringFileName;
        // sanity check
        if (filename.equals("")) {
            writeToUiToast("scan a tag before writing the content to a file :-)");
            return;
        }
        intent.putExtra(Intent.EXTRA_TITLE, filename);
        selectTextFileActivityResultLauncher.launch(intent);
    }

    ActivityResultLauncher<Intent> selectTextFileActivityResultLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            new ActivityResultCallback<ActivityResult>() {
                @Override
                public void onActivityResult(ActivityResult result) {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        // There are no request codes
                        Intent resultData = result.getData();
                        // The result data contains a URI for the document or directory that
                        // the user selected.
                        Uri uri = null;
                        if (resultData != null) {
                            uri = resultData.getData();
                            // Perform operations on the document using its URI.
                            try {
                                // get file content from edittext
                                String fileContent = exportString;
                                System.out.println("## data to write: " + exportString);
                                writeTextToUri(uri, fileContent);
                                writeToUiToast("file written to external shared storage: " + uri.toString());
                            } catch (IOException e) {
                                e.printStackTrace();
                                writeToUiToast("ERROR: " + e.toString());
                                return;
                            }
                        }
                    }
                }
            });

    private void writeTextToUri(Uri uri, String data) throws IOException {
        try {
            System.out.println("** data to write: " + data);
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(getApplicationContext().getContentResolver().openOutputStream(uri));
            outputStreamWriter.write(data);
            outputStreamWriter.close();
        } catch (IOException e) {
            System.out.println("Exception File write failed: " + e.toString());
        }
    }

    /**
     * options menu show licenses
     */

    // run: displayLicensesAlertDialog();
    // display licenses dialog see: https://bignerdranch.com/blog/open-source-licenses-and-android/
    private void displayLicensesAlertDialog() {
        WebView view = (WebView) LayoutInflater.from(this).inflate(R.layout.dialog_licenses, null);
        view.loadUrl("file:///android_asset/open_source_licenses.html");
        android.app.AlertDialog mAlertDialog = new android.app.AlertDialog.Builder(MainActivity.this).create();
        mAlertDialog = new android.app.AlertDialog.Builder(this, R.style.Theme_TalkToYourCreditCard)
                .setTitle(getString(R.string.action_licenses))
                .setView(view)
                .setPositiveButton(android.R.string.ok, null)
                .show();
    }

    /**
     * section for OptionsMenu
     */

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_activity_main, menu);

        MenuItem mCopyData = menu.findItem(R.id.action_copy_data);
        mCopyData.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(@NonNull MenuItem menuItem) {
                ClipboardManager clipboard = (ClipboardManager)
                        getSystemService(Context.CLIPBOARD_SERVICE);
                ClipData clip = ClipData.newPlainText("BasicNfcEmvReader", etLog.getText());
                clipboard.setPrimaryClip(clip);
                // show toast only on Android versions < 13
                if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.S_V2)
                    Toast.makeText(getApplicationContext(), "copied", Toast.LENGTH_SHORT).show();
                return false;
            }
        });

        MenuItem mExportTextFile = menu.findItem(R.id.action_export_text_file);
        mExportTextFile.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Log.i(TAG, "mExportTextFile");
                exportTextFile();
                return false;
            }
        });

        MenuItem mLicenses = menu.findItem(R.id.action_licenses);
        mLicenses.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Log.i(TAG, "mLicenses");
                displayLicensesAlertDialog();
                return false;
            }
        });

        MenuItem mAbout = menu.findItem(R.id.action_about);
        mAbout.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Log.i(TAG, "mAbout");
                View aboutPage = new AboutPage(context)
                        .isRTL(false)
                        .setDescription(getString(R.string.app_description))
                        //.setCustomFont(String) // or Typeface
                        .setImage(R.drawable.ic_launcher_playstore)
                        .addItem(new Element().setTitle("Version 1.0"))
                        .addGroup("Connect with us")
                        .addEmail("androidcrypto@gmx.de")
                        .addWebsite("https://medium.com/@androidcrypto")
                        .addGitHub("androidcrypto")
                        .addItem(getCopyRightsElement())
                        .create();
                setContentView(aboutPage);
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }

    Element getCopyRightsElement() {
        Element copyRightsElement = new Element();
        final String copyrights = String.format(getString(R.string.copy_right), Calendar.getInstance().get(Calendar.YEAR));
        copyRightsElement.setTitle(copyrights);
        copyRightsElement.setIconDrawable(R.drawable.about_icon_copy_right);
        copyRightsElement.setAutoApplyIconTint(true);
        copyRightsElement.setIconTint(mehdi.sakout.aboutpage.R.color.about_item_icon_color);
        copyRightsElement.setIconNightTint(android.R.color.white);
        copyRightsElement.setGravity(Gravity.CENTER);
        copyRightsElement.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Toast.makeText(MainActivity.this, copyrights, Toast.LENGTH_SHORT).show();
            }
        });
        return copyRightsElement;
    }
}