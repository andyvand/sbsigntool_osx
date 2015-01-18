#include "efivars.h"
#include <stdio.h>
#include <stdlib.h>

void PrintEFITime(EFI_TIME time)
{
    printf("<- Time Data ->\n");
    printf("Date: %u/%u/%u\n", time.Day, time.Month, time.Year);
    printf("Time: %u:%u:%u\n", time.Hour, time.Minute, time.Second);
    printf("Nanotime: %u\n", time.Nanosecond);
    printf("Timezone: %d\n", time.TimeZone);
    printf("Daylight: %u\n", time.Daylight);
    printf("<- End of time data ->\n");
}

void PrintGuid(EFI_GUID guid)
{
    printf("EFI GUID: {0x%.8X, 0x%.4X, 0x%.4X, {0x%.2X, 0x%.2X, 0x%.2X, 0x%.2X, 0x%.2X, 0x%.2X, 0x%.2X, 0x%.2X}}\n", guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
}

void PrintHex(void *input, int length)
{
    unsigned char *HexBytes = input;
    int divisor = 0;
    int current = 0;

    while (current < length)
    {
        if (divisor >= 32)
        {
            printf("\n");
            divisor = 0;
        }

        printf("%.2X", HexBytes[current]);

        ++divisor;
        ++current;
    }

    printf("\n");
}

int DumpCertData(WIN_CERTIFICATE cert)
{
    printf("Certificate length: 0x%X\n", cert.dwLength);
    printf("Certificate revision: 0x%X\n", cert.wRevision);
    printf("Certificate type: 0x%X\n", cert.wCertificateType);

    return(cert.dwLength);
}

void *DumpSecHeader(void *input, unsigned int *seclength)
{
    EFI_VARIABLE_AUTHENTICATION_2 *auth_descriptor = input;
    int certlength;

    printf("<== Variable Authentication 2 header ==>\n");

    PrintEFITime(auth_descriptor->TimeStamp);

    printf("<- Certificate data ->\n");
    certlength = DumpCertData(auth_descriptor->AuthInfo.Hdr);
    printf("Certificate type ");
    PrintGuid(auth_descriptor->AuthInfo.CertType);

    if (certlength > 0x18)
    {
        printf("<- Signed data ->\n");
        PrintHex((void *)auth_descriptor->AuthInfo.CertData, certlength - 0x18);
        printf("<- End of signed data ->\n");
    }
    printf("<- End of certificate data ->\n");

    printf("<== End of Variable Authentication 2 header ==>\n\n");

    *seclength = sizeof(EFI_TIME) + certlength;

    return (input + *seclength);
}

unsigned int DumpSiglist(void *input, int number)
{
    EFI_SIGNATURE_LIST *siglist = input;
    EFI_SIGNATURE_DATA *sigdata = (input + sizeof(EFI_SIGNATURE_LIST));

    printf("<== Signature list %d ==>\n", number);

    printf("<- Signature list header ->\n");
    printf("Signature type ");
    PrintGuid(siglist->SignatureType);
    printf("Signature list size: 0x%X\n", siglist->SignatureListSize);
    printf("Signature header size: 0x%X\n", siglist->SignatureHeaderSize);
    printf("Signature size: 0x%X\n", siglist->SignatureSize);
    printf("<- End of signature list header ->\n");

    printf("<- Signature data ->\n");
    printf("Signature owner ");
    PrintGuid(sigdata->SignatureOwner);
    printf("<-Signature ->\n");
    PrintHex(sigdata->SignatureData, (siglist->SignatureSize - sizeof(EFI_GUID)));
    printf("<- End of signature ->\n");
    printf("<- End of signature data ->\n");
    printf("<== End of signature list %d ==>\n\n", number);

    return((unsigned int)siglist->SignatureListSize);
}

void Usage(char *progname)
{
    printf("%s - program to extract info from PK, KEK, db and dbx files\n", progname);
    printf("Copyright (C) 2013 AnV Software\n");
}

int main(int argc, char **argv)
{
    FILE *f = NULL;
    char *DataPointer = NULL;
    char *buffer = NULL;
    unsigned int buffercount = 0;
    unsigned int currentlength = 0;
    unsigned int listlength = 0;
    int listnumber = 1;

    if (argc != 2)
    {
        Usage(argv[0]);
        return(1);
    }

    f = fopen(argv[1], "rb");
    fseek(f, 0, SEEK_END);
    buffercount = (unsigned int)ftell(f);
    fseek(f, 0, SEEK_SET);

    buffer = malloc(buffercount);

    fread(buffer, buffercount, 1, f);
    fclose(f);

    DataPointer = DumpSecHeader(buffer, &currentlength);

    while (currentlength < buffercount)
    {
        listlength = DumpSiglist(DataPointer, listnumber);
        currentlength += listlength;

        if (currentlength < buffercount)
        {
            DataPointer += listlength;
            ++listnumber;
        }
    }

    free(buffer);

    return(0);
}
