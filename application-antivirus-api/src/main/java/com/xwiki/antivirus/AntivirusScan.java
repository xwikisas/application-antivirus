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
package com.xwiki.antivirus;

import java.util.Date;

import org.xwiki.stability.Unstable;

/**
 * The result of an Antivirus Job scan.
 *
 * @version $Id$
 * @since 1.5
 */
@Unstable
public class AntivirusScan
{
    private final Date startDate;

    private final Date endData;

    private final int scannedFiles;

    public AntivirusScan(Date startDate, Date endData, int scannedFiles)
    {
        this.startDate = startDate;
        this.endData = endData;
        this.scannedFiles = scannedFiles;
    }

    /**
     * @return the date when the scan started
     */
    public Date getStartDate()
    {
        return startDate;
    }

    /**
     * @return the date when the scan finished
     */
    public Date getEndData()
    {
        return endData;
    }

    /**
     * @return the number of files that were scanned during the job
     */
    public int getScannedFiles()
    {
        return scannedFiles;
    }
}
