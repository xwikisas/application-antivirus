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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Provider;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.slf4j.Logger;
import org.xwiki.bridge.event.DocumentCreatingEvent;
import org.xwiki.bridge.event.DocumentUpdatingEvent;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.component.util.ReflectionUtils;
import org.xwiki.diff.Delta;
import org.xwiki.model.reference.AttachmentReference;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.observation.event.CancelableEvent;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.AttachmentDiff;
import com.xpn.xwiki.doc.XWikiAttachment;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xwiki.antivirus.AntivirusConfiguration;
import com.xwiki.antivirus.AntivirusEngine;
import com.xwiki.antivirus.AntivirusException;
import com.xwiki.antivirus.AntivirusLog;
import com.xwiki.antivirus.ScanResult;
import com.xwiki.licensing.Licensor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link AttachmentUploadedEventListener}.
 *
 * @version $Id$
 */
@ComponentTest
class AttachmentUploadedEventListenerTest
{
    private static final String ENGINE_NAME = "clamav";

    @InjectMockComponents
    private AttachmentUploadedEventListener eventListener;

    @MockComponent
    private Logger logger;

    @MockComponent
    private AntivirusConfiguration configuration;

    @MockComponent
    private Provider<Licensor> licensorProvider;

    @MockComponent
    private AntivirusLog antivirusLog;

    @MockComponent
    private ComponentManager componentManager;

    @Mock
    private Licensor licensor;

    @Mock
    private CancelableEvent event;

    @Mock
    private XWikiContext context;

    @Mock
    private XWikiDocument doc;

    @Mock
    private XWikiDocument orignalDoc;

    private DocumentReference docReference;

    private DocumentReference userReference;

    private List<XWikiAttachment> attachmentList;

    private XWikiAttachment attachment1;

    private XWikiAttachment attachment2;

    private AttachmentReference attachmentReference;

    @Mock
    private AntivirusEngine engine;

    private ScanResult scanResult;

    @BeforeEach
    void setUp() throws Exception
    {
        ReflectionUtils.setFieldValue(this.eventListener, "logger", this.logger);
        when(configuration.isEnabled()).thenReturn(true);
        when(configuration.getDefaultEngineName()).thenReturn(ENGINE_NAME);
        when(componentManager.getInstance(AntivirusEngine.class, ENGINE_NAME)).thenReturn(engine);
        when(licensorProvider.get()).thenReturn(licensor);

        event = spy(new DocumentUpdatingEvent());

        doc = mock(XWikiDocument.class);
        docReference = new DocumentReference("wiki", "Space", "Page");
        when(doc.getDocumentReference()).thenReturn(docReference);

        when(doc.clone()).thenReturn(doc);

        orignalDoc = mock(XWikiDocument.class);
        when(doc.getOriginalDocument()).thenReturn(orignalDoc);

        attachmentList = new ArrayList<>();
        when(doc.getAttachmentList()).thenReturn(attachmentList);

        // Use the same reference since the attachments are supposed to be versions of the same file in these tests.
        attachmentReference = new AttachmentReference("file.ext", docReference);

        attachment1 = mock(XWikiAttachment.class);
        when(attachment1.getReference()).thenReturn(attachmentReference);

        attachment2 = mock(XWikiAttachment.class);
        when(attachment2.getReference()).thenReturn(attachmentReference);

        when(logger.isDebugEnabled()).thenReturn(true);

        context = mock(XWikiContext.class);
        userReference = new DocumentReference("wiki", "XWiki", "user");
        when(context.getUserReference()).thenReturn(userReference);
        when(context.getMainXWiki()).thenReturn("xwiki");

        when(licensor.hasLicensure(new DocumentReference(context.getMainXWiki(), "Antivirus", "ConfigurationClass")))
            .thenReturn(true);

        scanResult = new ScanResult(attachmentReference, true, Collections.emptyList());
    }

    @Test
    void antivirusDisabled() throws Exception
    {
        when(configuration.isEnabled()).thenReturn(false);

        when(logger.isDebugEnabled()).thenReturn(true);

        eventListener.onEvent(event, doc, context);

        verify(logger, times(1)).debug(
            "Skipping attachment scan for event [{}] by user [{}] on document [{}]. Antivirus is disabled.",
            event.getClass().getName(), userReference, docReference);

        verify(doc, times(1)).getDocumentReference();

        // Make sure execution stops before checking the doc attachments.
        verifyNoMoreInteractions(doc);
    }

    @Test
    void noAttachmentsNewDocument() throws Exception
    {
        event = new DocumentCreatingEvent();

        eventListener.onEvent(event, doc, context);

        verify(doc, times(1)).getAttachmentList();

        // Make sure execution stops before checking license.
        verifyNoInteractions(licensor);

        // Make sure no scanning is performed.
        verifyNoInteractions(engine);
    }

    @Test
    void noAttachmentsChangedExistingDocument() throws Exception
    {
        // No attachment changes.
        when(doc.getAttachmentDiff(orignalDoc, doc, context)).thenReturn(Collections.emptyList());

        eventListener.onEvent(event, doc, context);

        // Make sure execution stops before checking license.
        verifyNoInteractions(licensor);

        // Make sure no scanning is performed.
        verifyNoInteractions(engine);
    }

    @Test
    void attachmentsChangedExistingDocumentNoLicense() throws Exception
    {
        AttachmentDiff attachmentdiff1 = new AttachmentDiff("file.ext", Delta.Type.INSERT, null, attachment1);
        AttachmentDiff attachmentdiff2 = new AttachmentDiff("file.ext", Delta.Type.CHANGE, attachment1, attachment2);
        AttachmentDiff attachmentdiff3 = new AttachmentDiff("file.ext", Delta.Type.DELETE, attachment2, null);
        List<AttachmentDiff> attachmentDiffs = Arrays.asList(attachmentdiff1, attachmentdiff2, attachmentdiff3);

        when(doc.getAttachmentDiff(orignalDoc, doc, context)).thenReturn(attachmentDiffs);

        when(licensor.hasLicensure(new DocumentReference(context.getMainXWiki(), "Antivirus", "ConfigurationClass")))
            .thenReturn(false);

        eventListener.onEvent(event, doc, context);

        verify(configuration, times(1)).isEnabled();

        verify(licensor, times(1))
            .hasLicensure(new DocumentReference(context.getMainXWiki(), "Antivirus", "ConfigurationClass"));

        // Make sure execution stops before getting the configured AV engine.
        verifyNoMoreInteractions(configuration);
    }

    @Test
    void attachmentsChangedExistingDocumentNoEngineImplementation() throws Exception
    {
        AttachmentDiff attachmentdiff1 = new AttachmentDiff("file.ext", Delta.Type.INSERT, null, attachment1);
        AttachmentDiff attachmentdiff2 = new AttachmentDiff("file.ext", Delta.Type.CHANGE, attachment1, attachment2);
        AttachmentDiff attachmentdiff3 = new AttachmentDiff("file.ext", Delta.Type.DELETE, attachment2, null);
        List<AttachmentDiff> attachmentDiffs = Arrays.asList(attachmentdiff1, attachmentdiff2, attachmentdiff3);

        when(doc.getAttachmentDiff(orignalDoc, doc, context)).thenReturn(attachmentDiffs);
        when(componentManager.getInstance(AntivirusEngine.class, ENGINE_NAME)).thenThrow(
            new ComponentLookupException("No component found"));
        eventListener.onEvent(event, doc, context);

        verify(licensor, times(1))
            .hasLicensure(new DocumentReference(context.getMainXWiki(), "Antivirus", "ConfigurationClass"));

        verify(logger, times(1)).error(
            eq("Failed to load antivirus engine [{}] to scan attachments for event [{}] by user [{}] on document [{}]"),
            eq(ENGINE_NAME), eq(event.getClass().getName()), eq(userReference), eq(docReference),
            any(ComponentLookupException.class));
    }

    @Test
    void attachmentsChangedExistingDocumentScanErrors() throws Exception
    {
        AttachmentDiff attachmentdiff1 = new AttachmentDiff("file.ext", Delta.Type.INSERT, null, attachment1);
        AttachmentDiff attachmentdiff2 = new AttachmentDiff("file.ext", Delta.Type.CHANGE, attachment1, attachment2);
        AttachmentDiff attachmentdiff3 = new AttachmentDiff("file.ext", Delta.Type.DELETE, attachment2, null);
        List<AttachmentDiff> attachmentDiffs = Arrays.asList(attachmentdiff1, attachmentdiff2, attachmentdiff3);

        when(doc.getAttachmentDiff(orignalDoc, doc, context)).thenReturn(attachmentDiffs);

        when(configuration.getDefaultEngineName()).thenReturn(ENGINE_NAME);

        when(engine.scan(attachment2)).thenReturn(scanResult);

        Exception exception = new AntivirusException("oops", null);
        when(engine.scan(attachment1)).thenThrow(exception);

        eventListener.onEvent(event, doc, context);

        verify(configuration, times(1)).isEnabled();

        verify(licensor, times(1))
            .hasLicensure(new DocumentReference(context.getMainXWiki(), "Antivirus", "ConfigurationClass"));

        verify(configuration, times(1)).getDefaultEngineName();

        // Make sure we only get to scan 2 times:
        // * once for the INSERT (results in a logged exception)
        verify(engine, times(1)).scan(attachment1);
        verify(logger, times(1)).error("Failed to scan attachment [{}] during event [{}] by user [{}]",
            attachmentReference, event.getClass().getName(), userReference, exception);
        // * once for the CHANGE
        verify(engine, times(1)).scan(attachment2);

        // Make sure no other scans are made (i.e. for the DELETE).
        verifyNoMoreInteractions(engine);

        // Make sure the event is not canceled, since no infections were found and the exception results in allowing the
        // attachment to be uploaded (i.e. due to a fault in the AV engine or the AV extension).
        verifyNoMoreInteractions(event);
    }

    @Test
    void attachmentsChangedExistingDocumentNoInfections() throws Exception
    {
        AttachmentDiff attachmentdiff1 = new AttachmentDiff("file.ext", Delta.Type.INSERT, null, attachment1);
        AttachmentDiff attachmentdiff2 = new AttachmentDiff("file.ext", Delta.Type.CHANGE, attachment1, attachment2);
        AttachmentDiff attachmentdiff3 = new AttachmentDiff("file.ext", Delta.Type.DELETE, attachment2, null);
        List<AttachmentDiff> attachmentDiffs = Arrays.asList(attachmentdiff1, attachmentdiff2, attachmentdiff3);

        when(doc.getAttachmentDiff(orignalDoc, doc, context)).thenReturn(attachmentDiffs);

        when(configuration.getDefaultEngineName()).thenReturn(ENGINE_NAME);

        when(engine.scan(attachment1)).thenReturn(scanResult);
        when(engine.scan(attachment2)).thenReturn(scanResult);

        eventListener.onEvent(event, doc, context);

        verify(configuration, times(1)).isEnabled();

        verify(licensor, times(1))
            .hasLicensure(new DocumentReference(context.getMainXWiki(), "Antivirus", "ConfigurationClass"));

        verify(configuration, times(1)).getDefaultEngineName();

        // Make sure we only get to scan 2 times:
        // * once for the INSERT.
        verify(engine, times(1)).scan(attachment1);
        // * once for the CHANGE.
        verify(engine, times(1)).scan(attachment2);

        // Make sure no other scans are made (i.e. for the DELETE).
        verifyNoMoreInteractions(engine);

        // Make sure the event is not canceled, since no infections were found and the exception results in allowing the
        // attachment to be uploaded (i.e. due to a fault in the AV engine or the AV extension).
        verifyNoMoreInteractions(event);
    }

    @Test
    void attachmentsChangedExistingDocumentInfectionsFound() throws Exception
    {
        AttachmentDiff attachmentdiff1 = new AttachmentDiff("file.ext", Delta.Type.INSERT, null, attachment1);
        AttachmentDiff attachmentdiff2 = new AttachmentDiff("file.ext", Delta.Type.CHANGE, attachment1, attachment2);
        AttachmentDiff attachmentdiff3 = new AttachmentDiff("file.ext", Delta.Type.DELETE, attachment2, null);
        List<AttachmentDiff> attachmentDiffs = Arrays.asList(attachmentdiff1, attachmentdiff2, attachmentdiff3);

        when(doc.getAttachmentDiff(orignalDoc, doc, context)).thenReturn(attachmentDiffs);

        when(configuration.getDefaultEngineName()).thenReturn(ENGINE_NAME);

        when(engine.scan(attachment1)).thenReturn(scanResult);

        ScanResult infectionResult =
            new ScanResult(attachmentReference, false, Arrays.asList("Here", "there", "be", "dragons"));
        when(engine.scan(attachment2)).thenReturn(infectionResult);

        eventListener.onEvent(event, doc, context);

        verify(configuration, times(1)).isEnabled();

        verify(licensor, times(1))
            .hasLicensure(new DocumentReference(context.getMainXWiki(), "Antivirus", "ConfigurationClass"));

        verify(configuration, times(2)).getDefaultEngineName();

        // Make sure we only get to scan 2 times:
        // * once for the INSERT.
        verify(engine, times(1)).scan(attachment1);
        // * once for the CHANGE.
        verify(engine, times(1)).scan(attachment2);

        // Check the warning is logged.
        verify(logger, times(1)).warn("Attachment [{}] found infected with [{}] during event [{}] by user [{}]",
            attachmentReference, infectionResult.getfoundViruses(), event.getClass().getName(), userReference);

        // Check the incident is logged in the antivirus log.
        verify(antivirusLog, times(1)).log(attachment2, infectionResult.getfoundViruses(), "blocked", "upload",
            ENGINE_NAME);

        // Make sure no other scans are made (i.e. for the DELETE).
        verifyNoMoreInteractions(engine);

        // Make sure the event is canceled and the reason is supplied.
        Map<AttachmentReference, Collection<String>> expectedInfectedAttachments = new HashMap<>();
        expectedInfectedAttachments.put(attachmentReference, infectionResult.getfoundViruses());
        verify(event, times(1))
            .cancel(String.format("Virus or malware infections found for attachments [%s] uploaded by user [%s]",
                expectedInfectedAttachments, userReference));
    }
}
