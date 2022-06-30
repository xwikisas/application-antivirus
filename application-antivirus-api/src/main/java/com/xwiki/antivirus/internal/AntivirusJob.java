/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package com.xwiki.antivirus.internal;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.quartz.SchedulerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.environment.Environment;
import org.xwiki.model.reference.AttachmentReference;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryManager;
import org.xwiki.wiki.descriptor.WikiDescriptorManager;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiAttachment;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.plugin.scheduler.AbstractJob;
import com.xpn.xwiki.web.Utils;
import com.xwiki.antivirus.AntivirusConfiguration;
import com.xwiki.antivirus.AntivirusEngine;
import com.xwiki.antivirus.AntivirusException;
import com.xwiki.antivirus.AntivirusLog;
import com.xwiki.antivirus.AntivirusReportSender;
import com.xwiki.antivirus.ScanResult;
import com.xwiki.licensing.Licensor;

/**
 * Periodically runs an antivirus scan on all attachments in the wiki.
 *
 * @version $Id$
 */
public class AntivirusJob extends AbstractJob
{
    private static final String JOB_START_TIME_KEY = "startTime";

    private static final String SCANNED_FILES_NR_KEY = "filesScanned";

    private static final String LAST_DOCUMENT_KEY = "lastDocument";

    public static final String PATH = "/jobs/status/antivirus/";

    public static final String JSON_FILE_NAME = "scan.properties";

    private static final Logger LOGGER = LoggerFactory.getLogger(AntivirusJob.class);

    private final Gson gson = new Gson();

    private int filesScanned = 0;

    @Override
    protected void executeJob(JobExecutionContext jobContext) throws JobExecutionException
    {
        // Make sure there are no two same Antivirus Jobs running at the same time. If the current job is not the
        // youngest, return.
        try {
            List<JobExecutionContext> activeAntivirusJobs = jobContext.getScheduler()
                .getCurrentlyExecutingJobs()
                .stream()
                .filter(job -> job.getJobDetail().getKey().getName().matches("[\\w\\d]+:Antivirus\\.AntivirusJob_\\d+"))
                .collect(Collectors.toList());
            if (activeAntivirusJobs.size() > 1 && !activeAntivirusJobs.stream()
                .min(Comparator.comparing(JobExecutionContext::getFireTime)).get().equals(jobContext))
            {
                LOGGER.warn("Stopped Antivirus Job from execution as there was another instance already running!");
                return;
            }
        } catch (SchedulerException e) {
            throw new RuntimeException(e);
        }
        XWikiContext context = getXWikiContext();

        // Create a json to store information about the progress of this Job. If the file already exists in the file
        // system, this means that a previous Job didn't finish properly and the current job will resume the scan
        // rather than start from scratch.
        String jsonPath = getJsonPath();
        JsonObject scanJson = createJson(jsonPath);

        AntivirusConfiguration antivirusConfiguration = Utils.getComponent(AntivirusConfiguration.class);
        if (!antivirusConfiguration.isEnabled()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Scheduled Antivirus scan is skipped. Antivirus is disabled.");
            }
            return;
        }

        // Skip if license has expired.
        Licensor licensor = Utils.getComponent(Licensor.class);
        if (!licensor.hasLicensure(new DocumentReference(context.getMainXWiki(), "Antivirus", "ConfigurationClass"))) {
            LOGGER.warn("Scheduled Antivirus scan is skipped. "
                + "No valid Antivirus license has been found. Please visit the 'Licenses' section in Administration.");
            return;
        }

        Date startDate = new Date(scanJson.getAsJsonPrimitive(JOB_START_TIME_KEY).getAsLong());

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Antivirus scheduled scan execution using engine [{}] has started...",
                antivirusConfiguration.getDefaultEngineName());
        }

        // Get the configured antivirus engine.
        AntivirusEngine antivirus = null;
        try {
            antivirus = Utils.getComponent(AntivirusEngine.class, antivirusConfiguration.getDefaultEngineName());
        } catch (Exception e) {
            LOGGER.error("Failed to load antivirus engine [{}] for scheduled scan.",
                antivirusConfiguration.getDefaultEngineName(), e);
            return;
        }

        List<String> wikiIds = null;
        try {
            wikiIds = Utils.getComponent(WikiDescriptorManager.class).getAllIds().stream().sorted()
                .collect(Collectors.toList());
        } catch (Exception e) {
            LOGGER.error("Failed to get the list of wikis to scan", e);
            return;
        }
        AntivirusLog antivirusLog = Utils.getComponent(AntivirusLog.class);

        // Resume the scan from the subwiki where the last scanned Document resided. The subwiki is inferred from the
        // document reference stored in the json.
        DocumentReferenceResolver<String> resolver = Utils.getComponent(DocumentReferenceResolver.TYPE_STRING);
        String previousScanWiki = scanJson.get(LAST_DOCUMENT_KEY).getAsString().isEmpty() ?
            "" : resolver.resolve(scanJson.get(LAST_DOCUMENT_KEY).getAsString()).getWikiReference().getName();
        int resumeIndex = Math.max(wikiIds.indexOf(previousScanWiki), 0);

        for (int i = resumeIndex; i < wikiIds.size(); i++) {
            scanWiki(wikiIds.get(i), antivirus, scanJson, jsonPath, antivirusLog,
                antivirusConfiguration.getDefaultEngineName());
        }

        Date endDate = new Date();

        // Send the report by email, if needed.
        maybeSendReport(startDate, endDate);

        // Delete the json, indicating that the scan finished successfully.
        try {
            Files.delete(Paths.get(jsonPath));
        } catch (IOException e) {
            LOGGER.warn("Antivirus Job Scan status file at [{}] could not be deleted when Job execution finished",
                jsonPath, e);
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Antivirus scheduled scan execution using engine [{}] has finished.",
                antivirusConfiguration.getDefaultEngineName());
        }
    }

    private void scanWiki(String wikiId, AntivirusEngine antivirus, JsonObject scanJson, String jsonPath,
        AntivirusLog antivirusLog, String engineHint)
    {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Scanning wiki [{}]...", wikiId);
        }

        // Get the list of scannable documents, that contain attachments.
        List<String> docsWithAttachments = null;
        QueryManager queryManager = Utils.getComponent(QueryManager.class);
        try {
            Query query = queryManager
                .createQuery("SELECT DISTINCT doc.fullName FROM XWikiDocument AS doc, XWikiAttachment AS attachment "
                    + "WHERE doc.id = attachment.docId ORDER BY doc.fullName", Query.HQL)
                .setWiki(wikiId);
            docsWithAttachments = query.execute();
        } catch (Exception e) {
            LOGGER.error("Failed to get the list of documents with attachments to scan for wiki [{}]", wikiId, e);
            return;
        }
        DocumentReferenceResolver<String> resolver = Utils.getComponent(DocumentReferenceResolver.TYPE_STRING);
        WikiReference wikiReference = new WikiReference(wikiId);
        // Resume the scan from the last successfully scanned document from the previous Job.
        List<DocumentReference> docRefs =
            docsWithAttachments.stream().map(docName -> resolver.resolve(docName, wikiReference))
                .collect(Collectors.toList());
        String previousScanDocument = scanJson.get(LAST_DOCUMENT_KEY).getAsString();
        OptionalInt indexOpt = IntStream.range(0, docRefs.size())
            .filter(i -> previousScanDocument.equals(docRefs.get(i).toString()))
            .findFirst();

        for (int i = indexOpt.isPresent() ? indexOpt.getAsInt() + 1 : 0; i < docsWithAttachments.size(); i++) {
            DocumentReference documentReference = resolver.resolve(docsWithAttachments.get(i), wikiReference);
            // After every scanned Document, persist its reference and the total number of scanned files, until that
            // point.
            scanDocument(documentReference, antivirus, scanJson, antivirusLog, engineHint);
            scanJson.addProperty(LAST_DOCUMENT_KEY, documentReference.toString());
            scanJson.addProperty(SCANNED_FILES_NR_KEY, filesScanned);
            persistJson(jsonPath, scanJson);
        }
    }

    private void scanDocument(DocumentReference documentReference, AntivirusEngine antivirus, JsonObject scanJson,
        AntivirusLog antivirusLog, String engineHint)
    {
        XWikiContext context = getXWikiContext();
        XWiki xwiki = context.getWiki();

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Scanning document [{}]...", documentReference);
        }

        XWikiDocument document = null;
        try {
            document = xwiki.getDocument(documentReference, context);
        } catch (Exception e) {
            LOGGER.error("Failed to scan attachments of document [{}]", documentReference, e);
            return;
        }
        // Used for generating AntivirusIncident document and logging.
        Map<XWikiAttachment, Collection<String>> deletedFilesForDoc = new HashMap<>();

        // Use a clone while iterating to avoid ConcurrentModificationExceptions while removing attachments.
        List<XWikiAttachment> attachmentsList = new ArrayList<>(document.getAttachmentList());

        for (XWikiAttachment attachment : attachmentsList) {
            scanAttachment(attachment, antivirus, document, deletedFilesForDoc, scanJson, antivirusLog, engineHint);
        }

        // Save the changes, if needed.
        if (deletedFilesForDoc.isEmpty()) {
            return;
        }

        // XWikiAttachment.toString() is not very useful when logging, so we need something better.
        Map<String, Collection<String>> loggingData = deletedFilesForDoc.entrySet()
            .stream()
            .collect(Collectors.toMap(e -> e.getKey().getFilename(), Map.Entry::getValue));
        // Delete infected files and generate an AntivirusIncident document for each of them.
        try {
            // Use the (scheduler job's) context user as author.
            document.setAuthorReference(context.getUserReference());

            xwiki.saveDocument(document, "[Antivirus Application] Automatically removed infected attachment(s)",
                context);
            for (Map.Entry<XWikiAttachment, Collection<String>> entry : deletedFilesForDoc.entrySet()) {
                logIncident(antivirusLog, entry.getKey(), entry.getValue(), "deleted", engineHint);
            }
            LOGGER.warn("Deleted infected attachments from document [{}]: [{}]", document.getDocumentReference(),
                loggingData);
        } catch (Exception e) {
            LOGGER.error("Failed to delete infected attachments from document [{}]: [{}]",
                document.getDocumentReference(), loggingData, e);
            for (Map.Entry<XWikiAttachment, Collection<String>> entry : deletedFilesForDoc.entrySet()) {
                logIncident(antivirusLog, entry.getKey(), entry.getValue(), "deleteFailed", engineHint);
            }
        }
    }

    private void scanAttachment(XWikiAttachment attachment, AntivirusEngine antivirus, XWikiDocument document,
        Map<XWikiAttachment, Collection<String>> deletedAttachmentsForDoc, JsonObject scanJson,
        AntivirusLog antivirusLog, String engineHint)
    {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Scanning attachment [{}]...", attachment.getReference());
        }

        ScanResult scanResult = null;
        try {
            scanResult = antivirus.scan(attachment);
            scanJson.addProperty(SCANNED_FILES_NR_KEY, ++filesScanned);
            if (scanResult.isClean()) {
                return;
            }
        } catch (Exception e) {
            // Log the exception.
            LOGGER.error("Failed to scan attachment [{}]", attachment.getReference(), e);
            // Files larger than the ClamAV configured size (default 25MB) will fail to be scanned. Attempting to scan
            // will throw the following errors. In the scan report we want to display a user friendly message, so we
            // create a new exception.
            String rootExceptionMessage = ExceptionUtils.getRootCauseMessage(e);
            List<String> knownErrors = Arrays.asList(
                "IOException: Broken pipe",
                "ScanFailureException: Scan failure: INSTREAM size limit exceeded. ERROR");
            if (knownErrors.contains(rootExceptionMessage)) {
                e = new AntivirusException("File size too large");
            }
            // Add it to the list of failed attachments, to be sent in the report.
            logIncident(antivirusLog, attachment, Collections.singletonList(ExceptionUtils.getRootCauseMessage(e)),
                "scanFailed", engineHint);
            // Nothing more to do for this attachment.
            return;
        }

        // Remove the infected attachment, without sending it to the RecycleBin.
        document.removeAttachment(attachment, false);

        // Remember the removed attachments for the current document.
        deletedAttachmentsForDoc.put(attachment, scanResult.getfoundViruses());
    }

    private void maybeSendReport(Date startDate, Date endDate)
    {
        AntivirusConfiguration antivirusConfiguration = Utils.getComponent(AntivirusConfiguration.class);

        QueryManager queryManager = Utils.getComponent(QueryManager.class);
        // Check if there are any incidents after the current scan.
        boolean existScanIncidents;
        try {
            existScanIncidents = !queryManager
                .createQuery("where doc.object(Antivirus.AntivirusIncidentClass).scanJobId > :docId", Query.XWQL)
                .setWiki(getXWikiContext().getMainXWiki())
                .bindValue("docId", startDate.getTime())
                .setLimit(1)
                .execute().isEmpty();
        } catch (QueryException e) {
            LOGGER.error("Failed to query for the incidents created during the scan.", e);
            return;
        }
        // Skip sending the report only when no infected attachments are found and report sending is not forced.
        if (!antivirusConfiguration.shouldAlwaysSendReport() && existScanIncidents) {
            LOGGER.debug("No-infections scheduled scan report sending is skipped. 'Always Send Report' is disabled.");
            return;
        }

        try {
            AntivirusReportSender reportSender = Utils.getComponent(AntivirusReportSender.class);
            reportSender.sendReport(startDate, endDate, filesScanned);
        } catch (Exception e) {
            try {
                // The report has failed to be sent. Log the incidents instead.
                Map<String, Map<AttachmentReference, Collection<String>>> incidents = getIncidents(startDate);
                LOGGER.error(
                    "Failed to send the infection report. Logging the report instead...\n"
                        + "Delete failed for infected attachments: [{}]\n" + "Deleted infected attachments: [{}]\n"
                        + "Scan failed attachments: [{}]\n" + "Start date: [{}]\n" + "End date: [{}]",
                    incidents.get("deleteFailed"), incidents.get("deleted"), incidents.get("scanFailed"), startDate,
                    endDate, e);
            } catch (QueryException | XWikiException ex) {
                LOGGER.error(
                    "Failed to send the infection report. Failed to log the incidents.", ex);
            }
        }
    }

    private JsonObject createJson(String path)
    {
        try {
            List<String> jsonFileContent = Files.readAllLines(Paths.get(path));
            JsonObject scanJson = gson.fromJson(String.join("", jsonFileContent), JsonObject.class);
            filesScanned = scanJson.getAsJsonPrimitive(SCANNED_FILES_NR_KEY).getAsInt();
            return scanJson;
        } catch (IOException e) {
            JsonObject scanJson = new JsonObject();
            scanJson.addProperty(JOB_START_TIME_KEY, System.currentTimeMillis());
            scanJson.addProperty(SCANNED_FILES_NR_KEY, 0);
            scanJson.addProperty(LAST_DOCUMENT_KEY, "");

            persistJson(path, scanJson);

            return scanJson;
        }
    }

    private String getJsonPath()
    {
        String jsonPath = Utils.getComponent(Environment.class).getPermanentDirectory().getAbsolutePath() + PATH;
        try {
            Files.createDirectories(Paths.get(jsonPath));
        } catch (IOException e) {
            LOGGER.warn("Could not create the path [{}] for the persisted status of the scan.", jsonPath, e);
        }
        jsonPath += JSON_FILE_NAME;
        return jsonPath;
    }

    private void persistJson(String jsonPath, JsonObject scanData)
    {
        try (PrintWriter out = new PrintWriter(new FileWriter(jsonPath))) {
            out.write(scanData.toString());
        } catch (IOException e) {
            LOGGER.warn("Failed to persist Antivirus Job status file.", e);
        }
    }

    private Map<String, Map<AttachmentReference, Collection<String>>> getIncidents(Date startDate)
        throws XWikiException, QueryException
    {
        XWikiContext context = getXWikiContext();
        QueryManager queryManager = Utils.getComponent(QueryManager.class);
        DocumentReferenceResolver<String> resolver = Utils.getComponent(DocumentReferenceResolver.TYPE_STRING);
        List<String> incidentDocNames = queryManager
            .createQuery("where doc.object(Antivirus.AntivirusIncidentClass).scanJobId > :docId", Query.XWQL)
            .setWiki(context.getMainXWiki())
            .bindValue("docId", startDate.getTime())
            .execute();

        Map<String, Map<AttachmentReference, Collection<String>>> incidents = new HashMap<>();
        for (String incidentDocName : incidentDocNames) {
            DocumentReference reference = resolver.resolve(incidentDocName, context.getMainXWiki());
            XWikiDocument doc = context.getWiki().getDocument(reference, context);
            BaseObject incidentObj = doc.getXObject(DefaultAntivirusLog.INCIDENT_CLASS_REFERENCE);
            DocumentReference docRef = resolver.resolve(incidentObj.getStringValue("attachmentDocument"));
            AttachmentReference attachmentRef =
                new AttachmentReference(incidentObj.getStringValue("attachmentName"), docRef);
            incidents.getOrDefault(incidentObj.getStringValue("incidentAction"), new HashMap<>())
                .put(attachmentRef, incidentObj.getListValue("attachmentInfections"));
        }
        return incidents;
    }

    private void logIncident(AntivirusLog antivirusLog, XWikiAttachment attachment, Collection<String> infections,
        String action, String engineHint)
    {
        try {
            antivirusLog.log(attachment, infections, action, "scheduledScan", engineHint);
        } catch (AntivirusException e) {
            LOGGER.error("Failed to log scheduled scan incident", e);
        }
    }
}
