function Get-CertificatePem {
    [CmdletBinding(DefaultParameterSetName = 'Url')]
    param(
        # e.g. https://contoso.com or https://contoso.com:8443
        [Parameter(ParameterSetName = 'Url', Mandatory, Position = 0)]
        [string]$Url,

        # Alternative: specify host and optional port directly
        [Parameter(ParameterSetName = 'Host', Mandatory)]
        [string]$ServerHost,

        [Parameter(ParameterSetName = 'Host')]
        [int]$Port = 443,

        # Include the chain (intermediates; use -IncludeRoot to also add the root)
        [switch]$IncludeChain,

        # Also include the root (only meaningful with -IncludeChain)
        [switch]$IncludeRoot,

        # Write the PEM to a file (if -IncludeChain, writes concatenated PEMs)
        [string]$OutFile,

        # Connect timeout in seconds
        [int]$TimeoutSeconds = 10
    )

    begin {
        function Convert-CertToPem {
            param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
            $alg = $Cert.PublicKey.Oid.FriendlyName
            Write-Verbose "Using ExportCertificatePem method for algorithm: $alg"
            # Use ExportCertificatePem if available (PowerShell 7+/newer .NET), else manual Base64
            $exportPem = $Cert | Get-Member -Name ExportCertificatePem -MemberType Method -ErrorAction SilentlyContinue
            if ($exportPem) {
                return $Cert.ExportCertificatePem()
            } else {
                $der = $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
                $b64 = [Convert]::ToBase64String($der)
                $lines = for ($i = 0; $i -lt $b64.Length; $i += 64) {
                    $b64.Substring($i, [Math]::Min(64, $b64.Length - $i))
                }
                return "-----BEGIN CERTIFICATE-----`n$($lines -join "`n")`n-----END CERTIFICATE-----"
            }
        }

        function Is-SelfSigned {
            param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
            # Fast heuristic
            return ($Cert.Subject -eq $Cert.Issuer)
        }
    }

    process {
        # Parse URL if provided
        if ($PSCmdlet.ParameterSetName -eq 'Url') {
            try {
                $uri = [Uri]$Url
            } catch {
                throw "Invalid URL: '$Url'."
            }

            if (-not $uri.Host) { throw "URL must include a host (e.g. https://example.com)." }
            $ServerHost = $uri.Host
            if ($uri.Port -gt 0 -and -not $uri.IsDefaultPort) {
                $Port = $uri.Port
            } else {
                # Default to 443 unless caller passed -Port in Host parameter set
                $Port = 443
            }
        }

        # Prepare TLS state capture via validation callback
        $state = [pscustomobject]@{
            Chain = $null
            Leaf  = $null
        }

        $callback = [System.Net.Security.RemoteCertificateValidationCallback]{
            param($sender, $cert, $chain, $errors)
            # Capture the leaf and the built chain OS provides during validation.
            # We accept regardless of validation errors – goal is to retrieve the cert.
            $state.Leaf  = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert)
            $state.Chain = $chain
            return $true
        }

        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            # Implement connect timeout
            $iar = $client.BeginConnect($ServerHost, $Port, $null, $null)
            if (-not $iar.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))) {
                try { $client.Close() } catch {}
                throw "Timed out connecting to $ServerHost`:$Port after $TimeoutSeconds seconds."
            }
            $client.EndConnect($iar)

            $netStream = $client.GetStream()
            $sslStream = [System.Net.Security.SslStream]::new($netStream, $false, $callback)
            try {
                # SNI is set via serverName parameter (targetHost)
                $options = [System.Net.Security.SslClientAuthenticationOptions]::new()
                $options.TargetHost = $ServerHost
                # Let system decide best protocols; you can set $options.EnabledSslProtocols if needed.
                $sslStream.AuthenticateAsClient($options)
            } finally {
                # We don't need to read/write any data; handshake suffices
                $sslStream.Dispose()
                $netStream.Dispose()
            }

            if (-not $state.Leaf) {
                throw "Failed to retrieve the server certificate from $ServerHost`:$Port."
            }

            # Build output list (leaf first)
            $certs = New-Object System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]
            $certs.Add($state.Leaf)

            if ($IncludeChain -and $state.Chain) {
                # chain.ChainElements order is leaf -> ... -> root (if available)
                for ($i = 1; $i -lt $state.Chain.ChainElements.Count; $i++) {
                    $certs.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]$state.Chain.ChainElements[$i].Certificate)
                }

                if (-not $IncludeRoot) {
                    # Remove trailing self-signed root if present
                    if ($certs.Count -gt 0 -and (Is-SelfSigned -Cert $certs[$certs.Count - 1])) {
                        [void]$certs.RemoveAt($certs.Count - 1)
                    }
                }
            }

            # Convert to PEM
            $pems = $certs | ForEach-Object { Convert-CertToPem $_ }

            if ($OutFile) {
                # Concatenate into one bundle file (common practice)
                $content = ($pems -join "`n")
                $null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutFile) -ErrorAction SilentlyContinue
                Set-Content -Path $OutFile -Value $content -NoNewline:$false -Encoding ascii
                return Get-Item $OutFile
            } else {
                # Write PEM(s) to pipeline (leaf only by default)
                $pems -join "`n"
            }
        } finally {
            try { $client.Dispose() } catch {}
        }
    }
}

Get-CertificatePem "https://graph.microsoft.com" -IncludeChain -IncludeRoot -OutFile "C:\temp\graph.pem" -Verbose