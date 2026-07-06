from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    database_url: str = "sqlite+aiosqlite:///./malware_pipeline.db"
    upload_dir: str = "./uploads"
    max_upload_bytes: int = 100 * 1024 * 1024  # 100 MB
    max_extract_files: int = 50
    max_extract_bytes: int = 100 * 1024 * 1024  # 100 MB total uncompressed

    anthropic_api_key: str = ""
    analysis_model: str = "claude-sonnet-4-6"
    enable_capa: bool = False
    enable_floss: bool = True
    enable_die: bool = True
    floss_timeout: int = 600  # seconds; set FLOSS_TIMEOUT in .env to tune
    triage_api_key: str = ""

    sandbox_api_key: str = ""
    sandbox_environment_id: int = 160  # Windows 10 64-bit; see sandbox_client.py for full list
    sandbox_poll_interval: int = 15    # seconds between state polls
    sandbox_timeout: int = 600         # max seconds to wait before SandboxTimeoutError

    virustotal_api_key: str = ""
    vt_request_delay: float = 15.0  # seconds between VT API calls; set VT_REQUEST_DELAY=0 in .env to skip (testing)
    osint_max_web_searches: int = 1   # cap on Claude web searches per OSINT call — 1 keeps it cheap (OSINT_MAX_WEB_SEARCHES in .env)
    static_max_tokens: int = 32000    # static phase on rich PE samples can be large; increase if truncated (STATIC_MAX_TOKENS in .env)
    osint_max_tokens: int = 8000      # OSINT output is compact; raise if truncated (OSINT_MAX_TOKENS in .env)
    correlation_max_tokens: int = 16000  # correlation fuses all phases; 8192 was too small (CORRELATION_MAX_TOKENS in .env)
    dynamic_max_tokens: int = 32000    # dynamic phase can be large (many processes + screenshots + ransom note); increase if truncated (DYNAMIC_MAX_TOKENS in .env)
    detection_max_tokens: int = 32000  # detection phase produces more output (YARA+Sigma+Suricata); increase if truncated (DETECTION_MAX_TOKENS in .env)
    report_max_tokens: int = 64000     # report is the longest output; 64000 is claude-sonnet-4-6's max output (REPORT_MAX_TOKENS in .env)

    elastic_url: str = ""
    elastic_api_key: str = ""
    kibana_url: str = ""

    # Sandbox routing: "triage" uses the Playwright browser bridge; "hybrid_analysis" uses the HA API
    dynamic_sandbox: str = "triage"  # DYNAMIC_SANDBOX in .env

    # Playwright bridge credentials (TEMPORARY — remove once Triage API research account approved)
    triage_email: str = ""     # TRIAGE_EMAIL in .env
    triage_password: str = ""  # TRIAGE_PASSWORD in .env

    # Replay Monitor screenshot capture (CAPTURE_SCREENSHOTS / SCREENSHOT_CAPTURE_SECS in .env)
    capture_screenshots: bool = True   # set False to skip the screenshot capture step entirely
    screenshot_capture_secs: int = 90  # seconds to wait while the replay plays; 3 frames are
                                       # captured at t=0, t/2, and t — set to video duration-5
                                       # to get the final ransomware frame (e.g. 144 for 2:29 vid)


settings = Settings()
