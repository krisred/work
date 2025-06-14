<?php

/**
 * Simple elFinder driver for Amazon S3 using Chilkat PHP extension
 *
 * @author Dmitry (dio) Levashov
 * @author Alexey Sukhotin
 * @author Naoki Sawada
 * @author Kris Red <krisred@example.com>
 * @version 2025-06-14 04:24:33
 **/
class elFinderVolumeS3Chilkat extends elFinderVolumeDriver {

	/**
	 * Driver id
	 * Must be started from letter and contains [a-z0-9]
	 * Used as part of volume id
	 *
	 * @var string
	 **/
	protected $driverId = 's3chk';

	/**
	 * Chilkat HTTP instance for S3 operations
	 *
	 * @var CkHttp
	 **/
	protected $http = null;

	/**
	 * Directory for tmp files
	 * If not set driver will try to use tmbDir as tmpDir
	 *
	 * @var string
	 **/
	protected $tmpPath = '';

	/**
	 * Bucket name
	 *
	 * @var string
	 **/
	protected $bucket = '';

	/**
	 * AWS Region
	 *
	 * @var string
	 **/
	protected $region = '';

	/**
	 * S3 access key
	 *
	 * @var string
	 **/
	protected $accessKey = '';

	/**
	 * S3 secret key
	 *
	 * @var string
	 **/
	protected $secretKey = '';

	/**
	 * AWS Session Token
	 *
	 * @var string
	 **/
	protected $sessionToken = '';

	/**
	 * Directory to store thumbnails
	 *
	 * @var string
	 **/
	protected $tmbPath = '';

	/**
	 * Path within bucket to use as root
	 *
	 * @var string
	 **/
	protected $basePath = '';

    /**
     * Chilkat license key
     *
     * @var string
     */
    protected $chilkatLicense = '';

	/**
	 * S3 endpoint URL
	 *
	 * @var string
	 */
	protected $endpoint = '';

	/**
	 * Use path style URL for S3 URLs
	 *
	 * @var boolean
	 **/
	protected $pathStyleUrl = false;

    /**
     * Skip bucket verification
     *
     * @var boolean
     */
    protected $skipBucketVerification = true;

    /**
     * File handles cache
     *
     * @var array
     */
    protected $handles = [];

	/**
	 * Constructor
	 * Extend options with required fields
	 *
	 * @author Dmitry (dio) Levashov
	 * @author Alexey Sukhotin
	 */
	public function __construct() {
		$opts = array(
			'accessKey'       => '',
			'secretKey'       => '',
			'sessionToken'    => '',
			'bucket'          => '',
			'region'          => 'us-west-2',
			'endpoint'        => 'https://s3.amazonaws.com',
			'pathStyleUrl'    => false,
			'path'            => '/',  // Path within bucket to use as root
			'separator'       => '/',  // Path separator for URL
			'alias'           => '',   // Display name of the root
			'URL'             => '',
			'tmbPath'         => '',
			'tmbURL'          => '',
			'tmpPath'         => '',
			'rootCssClass'    => 'elfinder-navbar-root-s3',
			'useApiTmb'       => true,
			'trashHash'       => false, // No trash folder
            'chilkatLicense'  => '',    // Chilkat license key
            'skipBucketVerification' => true, // Skip bucket verification when permissions are limited
		);
		$this->options = array_merge($this->options, $opts);
		$this->options['mimeDetect'] = 'internal';
	}

	/**
	 * Configure after successful mount.
	 *
	 * @return bool
	 **/
	protected function configure() {
		// Call parent configure first
		$result = parent::configure();
		if ($result === false) {
			return false;
		}

        error_log("Configure - original path: '" . $this->options['path'] . "'");

		    // Set the base path for restricting access
        if (!empty($this->options['path'])) {
            // Normalize base path to ensure it has trailing '/'
            $this->basePath = trim($this->options['path'], '/');
            if (!empty($this->basePath)) {
                $this->basePath .= '/';
            }
        } else {
            $this->basePath = '';
        }

        error_log("Configure - base path set to: '" . $this->basePath . "'");

		// Set up temporary path
		if (!$this->options['tmpPath']) {
			if ($this->tmbPath && is_writable($this->tmbPath)) {
				$this->tmpPath = $this->tmbPath;
			} else {
				$this->tmpPath = sys_get_temp_dir();
			}
		} else {
			$this->tmpPath = $this->options['tmpPath'];
		}

		// Make sure tmpPath is writable
		if (!is_dir($this->tmpPath)) {
            if (!@mkdir($this->tmpPath, 0755, true)) {
                $this->tmpPath = sys_get_temp_dir();
            }
        }

		if (!is_writable($this->tmpPath)) {
			// Try to use system temp directory
			$this->tmpPath = sys_get_temp_dir();
			if (!is_writable($this->tmpPath)) {
				return $this->setError('Temporary directory is not writable: ' . $this->tmpPath);
			}
		}

		// Set the display name of the root (alias)
		if (empty($this->options['alias'])) {
			// If alias is not set, use the last part of the path
			if (!empty($this->basePath)) {
				$parts = explode('/', rtrim($this->basePath, '/'));
				$this->options['alias'] = end($parts);
			} else {
				$this->options['alias'] = $this->bucket;
			}
		}

		// Normalize the base URL
		if ($this->options['URL'] && substr($this->options['URL'], -1) !== '/') {
			$this->options['URL'] .= '/';
		}

        // Store the Chilkat license key
        $this->chilkatLicense = $this->options['chilkatLicense'];

        // Store the skipBucketVerification flag
        if (isset($this->options['skipBucketVerification'])) {
            $this->skipBucketVerification = (bool)$this->options['skipBucketVerification'];
        }

		return true;
	}

/**
 * Prepare driver before mount volume.
 * Connect to AWS S3
 *
 * @return bool
 **/
protected function init() {
    // Check if the Chilkat classes exist
    if (!class_exists('CkGlobal')) {
        return $this->setError('Required Chilkat class CkGlobal not found.');
    }

    if (!class_exists('CkHttp')) {
        return $this->setError('Required Chilkat class CkHttp not found.');
    }

    if (!class_exists('CkXml')) {
        return $this->setError('Required Chilkat class CkXml not found.');
    }

    $this->accessKey = isset($this->options['accessKey']) ? $this->options['accessKey'] : '';
    $this->secretKey = isset($this->options['secretKey']) ? $this->options['secretKey'] : '';
    $this->sessionToken = isset($this->options['sessionToken']) ? $this->options['sessionToken'] : '';
    $this->bucket = isset($this->options['bucket']) ? $this->options['bucket'] : '';
    $this->region = isset($this->options['region']) ? $this->options['region'] : 'us-west-2';
    $this->endpoint = isset($this->options['endpoint']) ? $this->options['endpoint'] : 'https://s3.amazonaws.com';
    $this->pathStyleUrl = isset($this->options['pathStyleUrl']) ? $this->options['pathStyleUrl'] : false;
    $this->chilkatLicense = isset($this->options['chilkatLicense']) ? $this->options['chilkatLicense'] : 'no license key';

    if (!$this->accessKey || !$this->secretKey || !$this->bucket) {
        $missing = [];
        if (!$this->accessKey) $missing[] = 'accessKey';
        if (!$this->secretKey) $missing[] = 'secretKey';
        if (!$this->bucket) $missing[] = 'bucket';
        return $this->setError('Required options are not set: ' . implode(', ', $missing));
    }

    try {
        // Initialize Chilkat library with global unlock
        $glob = new CkGlobal();

        // Use provided license key or fall back to trial
        $success = $glob->UnlockBundle($this->chilkatLicense);

        if ($success !== true) {
            return $this->setError('Chilkat unlock failed: ' . $glob->lastErrorText());
        }

        // Initialize the HTTP component for S3 operations
        $this->http = new CkHttp();

        // Set AWS credentials
        $this->http->put_AwsAccessKey($this->accessKey);
        $this->http->put_AwsSecretKey($this->secretKey);

        if ($this->sessionToken) {
            $this->http->put_AwsSessionToken($this->sessionToken);
        }

        // Set AWS region
        $this->http->put_AwsRegion($this->region);

        // Set path-style URL if requested
        if ($this->pathStyleUrl) {
            $this->http->put_S3PathStyle(true);
        }

        // Skip bucket verification if the flag is set
        if (!$this->skipBucketVerification) {
            // The old way - requires ListBuckets permission
            $xml = $this->http->s3_ListBucketObjects();
            if (!$this->http->get_LastMethodSuccess()) {
                return $this->setError('S3 connection error: ' . $this->http->lastErrorText());
            }

            // Use SimpleXML instead of complex CkXml traversal
            try {
                $xmlObj = new SimpleXMLElement($xml);
                $bucketFound = false;
                if (isset($xmlObj->Buckets)) {
                    foreach ($xmlObj->Buckets->Bucket as $bucket) {
                        if ((string)$bucket->Name === $this->bucket) {
                            $bucketFound = true;
                            break;
                        }
                    }
                }

                if (!$bucketFound) {
                    return $this->setError('Specified bucket not found: ' . $this->bucket);
                }
            } catch (Exception $e) {
                return $this->setError('Failed to parse S3 response: ' . $e->getMessage());
            }
        } else {
            // The new way - just try to list objects in the bucket
            $bucketPath = $this->getBucketPath();
            $xml = $this->http->s3_ListBucketObjects($bucketPath);
            if (!$this->http->get_LastMethodSuccess()) {
                return $this->setError('Failed to access bucket: ' . $this->http->lastErrorText());
            }
        }

        // Verify the bucket exists and we can access it
        try {
            $bucketPath = $this->getBucketPath();
            error_log("Testing bucket access: " . $bucketPath);

            // Try listing objects to check access
            $xml = $this->http->s3_ListBucketObjects($bucketPath);
            if (!$this->http->get_LastMethodSuccess()) {
                return $this->setError('Failed to access bucket: ' . $this->http->lastErrorText());
            }

            // If a base path is specified, verify it exists or create it
            if (!empty($this->basePath)) {
                error_log("Verifying base path exists: " . $this->basePath);

                // Check if objects with this prefix exist
                $xml = $this->http->s3_ListBucketObjects($bucketPath, $this->basePath);
                if (!$this->http->get_LastMethodSuccess()) {
                    return $this->setError('Failed to check base path: ' . $this->http->lastErrorText());
                }

                // Check if we need to create the base path directory
                $needToCreate = true;
                try {
                    $xmlObj = new SimpleXMLElement($xml);
                    if (isset($xmlObj->Contents) && count($xmlObj->Contents) > 0) {
                        foreach ($xmlObj->Contents as $content) {
                            $key = (string)$content->Key;
                            if ($key === $this->basePath || strpos($key, $this->basePath) === 0) {
                                $needToCreate = false;
                                break;
                            }
                        }
                    }
                } catch (Exception $e) {
                    error_log("Error parsing XML: " . $e->getMessage());
                }

                // Create the directory marker if needed
                if ($needToCreate) {
                    error_log("Creating base path: " . $this->basePath);
                    $success = $this->http->S3_UploadString('', 'utf-8', 'application/x-directory', $bucketPath, $this->basePath);
                    if (!$success) {
                        return $this->setError('Failed to create base directory: ' . $this->http->lastErrorText());
                    }
                }
            }

            // Force stat the root to ensure it's properly cached
            $this->stat('/');

            return true;
        } catch (Exception $e) {
            return $this->setError('S3 initialization error: ' . $e->getMessage());
        }
    } catch (Exception $e) {
        return $this->setError('S3 initialization error: ' . $e->getMessage());
    }
}

/**
 * Return parent directory path
 *
 * @param  string  $path  file path
 * @return string
 **/
protected function _dirname($path) {
    if ($path === '/' || $path === '' || strpos($path, '/') === false) {
        return '/';
    }
    $dir = dirname($path);
    return $dir === '.' ? '/' : $dir;
}

	/**
	 * Return file name
	 *
	 * @param  string  $path  file path
	 * @return string
	 **/
	protected function _basename($path) {
		return basename($path);
	}

	/**
	 * Join dir name and file name and return full path
	 *
	 * @param  string  $dir   parent dir path
	 * @param  string  $name  file name
	 * @return string
	 **/
	protected function _joinPath($dir, $name) {
		return $dir == '/' ? '/'.$name : $dir.'/'.$name;
	}

	/**
	 * Return normalized path
	 *
	 * @param  string  $path  file path
	 * @return string
	 **/
	protected function _normpath($path) {
		$path = str_replace('\\', '/', $path);
		$path = rtrim($path, '/');
		if ($path === '') {
			$path = '/';
		}
		return $path;
	}

	/**
	 * Return file path related to root dir
	 *
	 * @param  string  $path  file path
	 * @return string
	 **/
	protected function _relpath($path) {
		if ($path === $this->root) {
			return '';
		}

		$path = substr($path, strlen($this->root)+1);

		if ($path === false) {
			$path = '';
		}

		return $path;
	}

	/**
	 * Return true if $path is children of $parent
	 *
	 * @param  string  $path    path to check
	 * @param  string  $parent  parent path
	 * @return bool
	 **/
	protected function _inpath($path, $parent) {
		$path = $this->_normpath($path);
		$parent = $this->_normpath($parent);

		if ($path === $parent) {
			return true;
		}

		$len = strlen($parent);

		return substr($path, 0, $len) === $parent && substr($path, $len, 1) === '/';
	}

	/**
	 * Return file source contents
	 *
	 * @param  string  $hash  file hash
	 * @param  array   $stat  file stat
	 * @return string|false
	 **/
	protected function _getContents_($hash, $stat) {
		if (($file = $this->file($hash)) == false || !$file['read']) {
			return $this->setError(elFinder::ERROR_PERM_DENIED);
		}

		return $this->_getContents($file['path']);
	}

	/**
	 * Put content in text file and return created file stat.
	 *
	 * @param  string  $hash     target directory hash
	 * @param  string  $name     file name
	 * @param  string  $content  text content
	 * @return array|false
	 **/
	protected function _filePutContents_($hash, $name, $content) {
		if (($dir = $this->dir($hash)) == false || !$dir['write']) {
			return $this->setError(elFinder::ERROR_PERM_DENIED);
		}

		$path = $this->decode($hash);
		$path = $this->_joinPath($path, $name);

		if ($this->_filePutContents($path, $content) === false) {
			return false;
		}

		return $this->stat($path);
	}

/**
 * Convert path relative to driver root to S3 object key
 *
 * @param string $path Path relative to volume root
 * @return string S3 object key
 */
protected function getObjectKey($path) {
    error_log("getObjectKey called for path: '$path'");

    // For root path (/ or empty), return the configured base path
    if ($path === '/' || $path === '') {
        error_log("getObjectKey: Root path, returning basePath: '" . $this->basePath . "'");
        return $this->basePath;
    }

    // Remove leading slash for proper path joining
    $path = ltrim($path, '/');

    // If the path already starts with the basePath, don't duplicate it
    if (!empty($this->basePath) && strpos($path, $this->basePath) === 0) {
        error_log("getObjectKey: Path already contains basePath, returning as is: '$path'");
        return $path;
    }

    // Combine basePath with the given path
    $result = !empty($this->basePath) ? rtrim($this->basePath, '/') . '/' . $path : $path;
    error_log("getObjectKey: Combined path: '$result'");
    return $result;
}

	/**
	 * Get full bucket path for S3 operations
	 *
	 * @return string
	 */
	protected function getBucketPath() {
		// Return bucket name without leading slash to fix URL formatting issue
		return $this->bucket;
	}

/**
 * Convert S3 object key to driver path (remove basePath)
 *
 * @param string $objectKey S3 object key
 * @return string Path relative to volume root
 */
protected function getPathFromKey($objectKey) {
    error_log("getPathFromKey called for objectKey: '$objectKey'");

    // If the key is the base path itself, return root path
    if ($objectKey === $this->basePath || $objectKey === rtrim($this->basePath, '/')) {
        error_log("getPathFromKey: Is basePath, returning root '/'");
        return '/';
    }

    // Remove basePath prefix from the key to get relative path
    if (!empty($this->basePath) && strpos($objectKey, $this->basePath) === 0) {
        $relativePath = '/' . substr($objectKey, strlen($this->basePath));
        error_log("getPathFromKey: Removing basePath, returning: '$relativePath'");
        return $relativePath;
    }

    // If there's no basePath or it doesn't match, return the full key with leading slash
    $result = '/' . $objectKey;
    error_log("getPathFromKey: No basePath match, returning: '$result'");
    return $result;
}

    /**
     * Check if the given object key is within the base path
     *
     * @param string $objectKey S3 object key
     * @return bool
     */
    protected function isInsideBase($objectKey) {
        // Empty base path means any key is accessible (full bucket access)
        if (empty($this->basePath)) {
            return true;
        }

        // If the object key is duplicated (contains multiple instances of basePath)
        // We'll normalize it first
        while (strpos($objectKey, $this->basePath . $this->basePath) === 0) {
            $objectKey = $this->basePath . substr($objectKey, strlen($this->basePath . $this->basePath));
        }

        // Check if the key starts with the base path
        return strpos($objectKey, $this->basePath) === 0;
    }

    /**
     * Return true if the file/directory should be hidden
     *
     * @param string $path file path
     * @param bool $isDir is directory
     * @return bool
     **/
    protected function _isHidden($path, $isDir = false) {
        $basename = basename($path);

        // Hide our marker file
        if ($basename === '_xtmpx.txt') {
            return true;
        }

        // Add any other hidden file patterns here
        if (substr($basename, 0, 1) === '.') {
            return true;
        }

        return false;
    }

	/**
	 * Check object exists
	 *
	 * @param string $path
	 * @return bool
	 */
	protected function objectExists($path) {
		$objectKey = $this->getObjectKey($path);

		// Empty key means root directory which always exists
		if ($objectKey === '' || $objectKey === '/') {
			return true;
		}

		// Base path always exists (ensured during init)
		if ($objectKey === $this->basePath) {
			return true;
		}

		// If checking directory, append trailing slash if not present
		if (substr($path, -1) !== '/') {
			$stat = $this->_stat($path);
			return $stat !== false;
		}

		try {
			// Use FileExists method to check if object exists
			$bucketPath = $this->getBucketPath();
			return $this->http->S3_FileExists($bucketPath, $objectKey);
		} catch (Exception $e) {
			return false;
		}
	}

	/**
	 * Check if object is a directory
	 *
	 * @param string $path
	 * @return bool
	 */
	protected function isObjectDir($path) {
		$objectKey = $this->getObjectKey($path);

		// Root is always a directory
		if ($objectKey === '' || $objectKey === '/') {
			return true;
		}

		// Base path is always a directory
		if ($objectKey === $this->basePath) {
			return true;
		}

		// Ensure the path has a trailing slash for directory check
		if (substr($objectKey, -1) !== '/') {
			$objectKey .= '/';
		}

		try {
			// First try a direct check on the directory marker
			$bucketPath = $this->getBucketPath();
			$exists = $this->http->S3_FileExists($bucketPath, $objectKey);
			if ($exists) {
				return true;
			}

			// If direct check fails, look for objects with this prefix
			$xml = $this->http->s3_ListBucketObjects($bucketPath);
			if (!$this->http->get_LastMethodSuccess()) {
				return false;
			}

            // Parse XML using SimpleXML for easier processing
            try {
                $xmlObj = new SimpleXMLElement($xml);
                foreach ($xmlObj->Contents as $content) {
                    $key = (string)$content->Key;
                    if (strpos($key, $objectKey) === 0) {
                        return true;
                    }
                }
            } catch (Exception $e) {
                // XML parsing failed
                return false;
            }

			return false;
		} catch (Exception $e) {
			return false;
		}
	}

	/**
	 * Create object stat cache
	 *
	 * @param string $path
	 * @param string $objectKey
	 * @param array $objectInfo
	 * @return array
	 */
	protected function createStatCache($path, $objectKey, $objectInfo = null) {
		$stat = [
			'size' => 0,
			'ts' => time(),
			'read' => true,
			'write' => true,
			'locked' => false,
			'hidden' => $this->_isHidden($path),
			'mime' => 'directory',
		];

		if ($objectInfo !== null) {
			if (isset($objectInfo['LastModified'])) {
				$stat['ts'] = strtotime($objectInfo['LastModified']);
			}

			if (isset($objectInfo['Size'])) {
                // This is a file, determine MIME type
                $ext = pathinfo($objectKey, PATHINFO_EXTENSION);
                $mime = $this->getMimeByExtension($ext);

				$stat = [
					'size' => intval($objectInfo['Size']),
					'ts' => $stat['ts'],
					'read' => true,
					'write' => true,
					'locked' => false,
					'hidden' => $this->_isHidden($path, false),
					'mime' => $mime ?: 'application/octet-stream',
				];
			}
		}

		// Set name based on path
		if ($path === '/' || $path === '') {
			$stat['name'] = $this->options['alias'] ?: 'Root';
		} else {
			$stat['name'] = basename($path);
		}

		return $stat;
	}

    /**
     * Get MIME type by file extension
     *
     * @param string $ext File extension
     * @return string MIME type
     */
    protected function getMimeByExtension($ext) {
        static $mimeMap = [
            'txt' => 'text/plain',
            'htm' => 'text/html',
            'html' => 'text/html',
            'php' => 'text/html',
            'css' => 'text/css',
            'js' => 'application/javascript',
            'json' => 'application/json',
            'xml' => 'application/xml',
            'swf' => 'application/x-shockwave-flash',
            'flv' => 'video/x-flv',

            // images
            'png' => 'image/png',
            'jpe' => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'jpg' => 'image/jpeg',
            'gif' => 'image/gif',
            'bmp' => 'image/bmp',
            'ico' => 'image/vnd.microsoft.icon',
            'tiff' => 'image/tiff',
            'tif' => 'image/tiff',
            'svg' => 'image/svg+xml',
            'webp' => 'image/webp',

            // archives
            'zip' => 'application/zip',
            'rar' => 'application/x-rar-compressed',
            'exe' => 'application/x-msdownload',
            'msi' => 'application/x-msdownload',
            'cab' => 'application/vnd.ms-cab-compressed',

            // audio/video
            'mp3' => 'audio/mpeg',
            'qt' => 'video/quicktime',
            'mov' => 'video/quicktime',
            'mp4' => 'video/mp4',
            'webm' => 'video/webm',
            'ogv' => 'video/ogg',

            // adobe
            'pdf' => 'application/pdf',
            'psd' => 'image/vnd.adobe.photoshop',
            'ai' => 'application/postscript',
            'eps' => 'application/postscript',
            'ps' => 'application/postscript',

            // ms office
            'doc' => 'application/msword',
            'rtf' => 'application/rtf',
            'xls' => 'application/vnd.ms-excel',
            'ppt' => 'application/vnd.ms-powerpoint',
            'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'pptx' => 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        ];

        $ext = strtolower($ext);
        return isset($mimeMap[$ext]) ? $mimeMap[$ext] : '';
    }

	/**
	 * Parse XML response from S3 to extract object info
	 *
	 * @param string $xml
	 * @param string $objectKey
	 * @return array|null
	 */
	protected function parseObjectInfo($xml, $objectKey) {
		if (!$xml) {
			return null;
		}

        // Use SimpleXML for easier XML parsing
        try {
            $xmlObj = new SimpleXMLElement($xml);
            foreach ($xmlObj->Contents as $content) {
                $key = (string)$content->Key;
                if ($key === $objectKey) {
                    return [
                        'Key' => $key,
                        'LastModified' => (string)$content->LastModified,
                        'ETag' => (string)$content->ETag,
                        'Size' => (string)$content->Size,
                        'StorageClass' => (string)$content->StorageClass
                    ];
                }
            }
        } catch (Exception $e) {
            // XML parsing failed
            return null;
        }

		return null;
	}

/**
 * Return file/dir stat for given path
 *
 * @param string $path file path
 * @return array|false
 **/
protected function _stat($path) {
    error_log("_stat called for path: '$path'");

    // Check if this is the root
    $isRoot = $path === '' || $path === '/';

    // Get key for the path
    $key = $this->getObjectKey($path);
    error_log("_stat key: '$key', isRoot: " . ($isRoot ? 'true' : 'false'));

    try {
        if ($isRoot) {
            // Root always exists with standard properties
            $stat = [
                'mime' => 'directory',
                'ts' => time(),
                'read' => 1,
                'write' => 1,
                'locked' => 1,
                'size' => 0,
                'dirs' => 1,
                'isroot' => 1,
                'name' => $this->options['alias'] ? $this->options['alias'] : 'Root',
                'hash' => $this->encode('/'),
                'phash' => '',  // Empty phash for root
                'volumeid' => $this->id,  // IMPORTANT: Add volume ID
            ];

            return $stat;
        }

        // Get the bucket path
        $bucketPath = $this->getBucketPath();

        // Normalize S3 object key to have trailing slash if it might be a directory
        $dirKey = $key;
        if (substr($dirKey, -1) !== '/') {
            $dirKey .= '/';
        }

        // First, check if it's a directory by looking for objects with this prefix
        $isDir = false;
        $hasItems = false;

        // Get all objects with the directory prefix
        $xml = $this->http->s3_ListBucketObjects($bucketPath, $dirKey);
        if ($this->http->get_LastMethodSuccess()) {
            try {
                $xmlObj = new SimpleXMLElement($xml);

                // Check for objects with this prefix
                if (isset($xmlObj->Contents)) {
                    foreach ($xmlObj->Contents as $content) {
                        $objKey = (string)$content->Key;

                        // If this is exactly our directory marker
                        if ($objKey === $dirKey) {
                            $isDir = true;
                            break;
                        }

                        // If there are objects with this prefix, it's a directory
                        if (strpos($objKey, $dirKey) === 0 && $objKey !== $key) {
                            $isDir = true;
                            $hasItems = true;
                            break;
                        }
                    }
                }
            } catch (Exception $e) {
                $this->setError("Error parsing XML in _stat: " . $e->getMessage());
            }
        }

        // If not identified as a directory, check if it exists as a file
        if (!$isDir) {
            // Check if file exists directly
            $exists = $this->http->S3_FileExists($bucketPath, $key);
            if (!$exists) {
                // Not a file and not a directory - doesn't exist
                $this->setError("Object does not exist: $key");
                return false;
            }

            // It's a file - try to get some basic information about it
            $fileSize = 0;
            $lastModified = time();

            // Try to get file information by listing bucket objects and finding this file
            $fileXml = $this->http->s3_ListBucketObjects($bucketPath);
            if ($this->http->get_LastMethodSuccess()) {
                try {
                    // Parse the XML to find our file
                    $xmlObj = new SimpleXMLElement($fileXml);
                    if (isset($xmlObj->Contents)) {
                        foreach ($xmlObj->Contents as $content) {
                            if ((string)$content->Key === $key) {
                                // Found our file in the listing
                                $fileSize = (int)$content->Size;

                                // Parse the last modified date
                                $lastModStr = (string)$content->LastModified;
                                if ($lastModStr) {
                                    try {
                                        $dt = new DateTime($lastModStr);
                                        $lastModified = $dt->getTimestamp();
                                    } catch (Exception $e) {
                                        // Keep default if date parsing fails
                                    }
                                }
                                break;
                            }
                        }
                    }
                } catch (Exception $e) {
                    $this->setError("Error parsing file info XML: " . $e->getMessage());
                }
            }

            // Determine mime type
            $mime = $this->mimetype($path);

            // Build file stat information
            $stat = [
                'mime' => $mime,
                'ts' => $lastModified,
                'read' => 1,
                'write' => 1,
                'locked' => 1,
                'size' => $fileSize,
                'name' => basename($path),
                'hash' => $this->encode($path),
                'phash' => $this->encode($this->_dirname($path)),
                'volumeid' => $this->id,  // Add volume ID
            ];

            return $stat;
        }

        // It's a directory
        $stat = [
            'mime' => 'directory',
            'ts' => time(), // We don't have accurate timestamps for directories in S3
            'read' => 1,
            'write' => 1,
            'locked' => 1,
            'size' => 0,
            'dirs' => 1, // Assume it might contain directories
            'name' => basename(rtrim($path, '/')),
            'hash' => $this->encode($path),
            'phash' => $this->encode($this->_dirname($path)),
            'volumeid' => $this->id,  // Add volume ID
        ];

        $this->setError("Directory stat for $path, parent: " . $this->_dirname($path));

        return $stat;

    } catch (Exception $e) {
        $this->setError("Error in _stat: " . $e->getMessage());
        return false;
    }
}
	/**
	 * Return true if path is a directory and has at least one child directory
	 *
	 * @param string $path file path
	 * @return bool
	 **/
	protected function _subdirs($path) {
		$objectKey = $this->getObjectKey($path);

		// Ensure directory key has trailing slash
		if (substr($objectKey, -1) !== '/') {
			$objectKey .= '/';
		}

		try {
			// List objects with the prefix to get directories
			$bucketPath = $this->getBucketPath();
			$xml = $this->http->s3_ListBucketObjects($bucketPath);
			if (!$this->http->get_LastMethodSuccess()) {
				return false;
			}

            // Parse XML using SimpleXML for easier processing
            try {
                $xmlObj = new SimpleXMLElement($xml);
                foreach ($xmlObj->Contents as $content) {
                    $key = (string)$content->Key;
                    // Check if key is a subdirectory (contains prefix + additional path component with trailing slash)
                    if ($objectKey === '' || (strpos($key, $objectKey) === 0 && $key !== $objectKey)) {
                        $relKey = substr($key, strlen($objectKey));
                        if (strpos($relKey, '/') !== false) {
                            return true;
                        }
                    }
                }
            } catch (Exception $e) {
                // XML parsing failed
                return false;
            }

			return false;
		} catch (Exception $e) {
			return false;
		}
	}

/**
 * Return array of children files and directories names
 *
 * @param string $path dir path
 * @return array
 **/
protected function _scandir($path) {
    error_log("_scandir called for path: '$path'");

    // Get S3 object key for this path
    $objectKey = $this->getObjectKey($path);
    error_log("_scandir objectKey: '$objectKey'");

    $result = [];

    // Ensure directory key has trailing slash except for root
    if ($objectKey !== '' && substr($objectKey, -1) !== '/') {
        $objectKey .= '/';
    }

    try {
        $bucketPath = $this->getBucketPath();
        error_log("_scandir bucketPath: '$bucketPath', prefix: '$objectKey'");

        // Try direct S3 ListObjects call
        $xml = $this->http->s3_ListBucketObjects($bucketPath, $objectKey);
        if (!$this->http->get_LastMethodSuccess()) {
            error_log("Failed to list bucket objects: " . $this->http->lastErrorText());
            return $this->setError('Failed to list bucket objects: ' . $this->http->lastErrorText());
        }

        // Parse XML using SimpleXML
        try {
            $xmlObj = new SimpleXMLElement($xml);
            $prefixLength = strlen($objectKey);
            $seenDirs = [];

            error_log("Found " . count($xmlObj->Contents) . " objects with prefix '$objectKey'");

            // Process each object returned by S3
            foreach ($xmlObj->Contents as $content) {
                $key = (string)$content->Key;
                error_log("Processing object: '$key'");

                // Skip objects that don't start with our prefix
                if ($objectKey !== '' && strpos($key, $objectKey) !== 0) {
                    error_log("Skipping '$key' - not matching prefix '$objectKey'");
                    continue;
                }

                // Skip the directory object itself
                if ($key === $objectKey) {
                    error_log("Skipping '$key' - is the directory itself");
                    continue;
                }

                // Get relative path from prefix
                $relKey = substr($key, $prefixLength);
                error_log("Relative key: '$relKey'");

                // Skip if empty
                if ($relKey === '') {
                    error_log("Skipping empty relative key");
                    continue;
                }

                // Handle directories (keys with trailing slash)
                if (substr($key, -1) === '/') {
                    $dirName = rtrim($relKey, '/');

                    // Skip empty directory names
                    if ($dirName === '') {
                        error_log("Skipping empty directory name");
                        continue;
                    }

                    // Only add the first level directory
                    if (strpos($dirName, '/') === false && !isset($seenDirs[$dirName])) {
                        error_log("Adding directory: '$dirName'");
                        $result[] = $dirName;
                        $seenDirs[$dirName] = true;
                    }
                    continue;
                }

                // Handle nested objects (extract first level dir or file)
                if (strpos($relKey, '/') !== false) {
                    // Extract first directory name
                    $parts = explode('/', $relKey, 2);
                    $dirName = $parts[0];

                    // Add directory if not seen yet
                    if (!isset($seenDirs[$dirName])) {
                        error_log("Adding directory from nested object: '$dirName'");
                        $result[] = $dirName;
                        $seenDirs[$dirName] = true;
                    }
                } else {
                    // This is a file directly in the current directory
                    error_log("Adding file: '$relKey'");
                    $result[] = $relKey;
                }
            }

        } catch (Exception $e) {
            error_log("XML parsing failed: " . $e->getMessage());
            return $this->setError('XML parsing failed: ' . $e->getMessage());
        }

        error_log("_scandir returning " . count($result) . " items: " . implode(", ", $result));
        return $result;
    } catch (Exception $e) {
        error_log("Exception in _scandir: " . $e->getMessage());
        return $this->setError('Exception in _scandir: ' . $e->getMessage());
    }
}

	/**
	 * Create directory
	 *
	 * @param string $path parent directory path
	 * @param string $name new directory name
	 * @return bool
	 **/
	protected function _mkdir($path, $name) {
		$dirPath = $this->_joinPath($path, $name);
		$objectKey = $this->getObjectKey($dirPath);

		// Ensure directory key has trailing slash
		if (substr($objectKey, -1) !== '/') {
			$objectKey .= '/';
		}

		// Ensure we're not creating outside our base path
		if (!$this->isInsideBase($objectKey)) {
			return false;
		}

		try {
			// Create an empty object with trailing slash to represent directory
			$bucketPath = $this->getBucketPath();
			$contentType = 'application/x-directory';
			return $this->http->S3_UploadString('', 'utf-8', $contentType, $bucketPath, $objectKey);
		} catch (Exception $e) {
			return false;
		}
	}

	/**
	 * Create file
	 *
	 * @param string $path parent directory path
	 * @param string $name new file name
	 * @return bool
	 **/
	protected function _mkfile($path, $name) {
		$filePath = $this->_joinPath($path, $name);
		$objectKey = $this->getObjectKey($filePath);

		// Ensure we're not creating outside our base path
		if (!$this->isInsideBase($objectKey)) {
			return false;
		}

		try {
			// Create an empty file by uploading an empty string
			$bucketPath = $this->getBucketPath();
			$contentType = 'text/plain';
			return $this->http->S3_UploadString('', 'utf-8', $contentType, $bucketPath, $objectKey);
		} catch (Exception $e) {
			return false;
		}
	}

	/**
	 * Copy file into another file
	 *
	 * @param string $source source file path
	 * @param string $targetDir target directory path
	 * @param string $name new file name
	 * @return bool
	 **/
	protected function _copy($source, $targetDir, $name) {
		// Since the Chilkat library doesn't have a direct copy object method,
		// we need to download and then upload the file

		$sourceKey = $this->getObjectKey($source);
		$targetPath = $this->_joinPath($targetDir, $name);
		$targetKey = $this->getObjectKey($targetPath);
		$bucketPath = $this->getBucketPath();

		// Ensure we're not copying outside our base path
		if (!$this->isInsideBase($sourceKey) || !$this->isInsideBase($targetKey)) {
			return false;
		}

		// Create a temporary file for the download
		$tmpPath = $this->tmpPath . DIRECTORY_SEPARATOR . md5($source . microtime(true));

		try {
			// Download source file
			$success = $this->http->S3_DownloadFile($bucketPath, $sourceKey, $tmpPath);
			if (!$success) {
				return false;
			}

			// Get content type of the file
            $ext = pathinfo($name, PATHINFO_EXTENSION);
            $contentType = $this->getMimeByExtension($ext);
            if (!$contentType && function_exists('mime_content_type')) {
                $contentType = mime_content_type($tmpPath) ?: 'application/octet-stream';
            } else if (!$contentType) {
                $contentType = 'application/octet-stream';
            }

			// Upload to the target location
			$success = $this->http->S3_UploadFile($tmpPath, $contentType, $bucketPath, $targetKey);

			unlink($tmpPath); // Clean up the temp file
			return $success;
		} catch (Exception $e) {
			if (file_exists($tmpPath)) {
				unlink($tmpPath); // Clean up on error
			}
			return false;
		}
	}

	/**
	 * Move file into another parent directory.
	 *
	 * @param string $source source file path
	 * @param string $targetDir target directory path
	 * @param string $name new file name
	 * @return bool
	 **/
	protected function _move($source, $targetDir, $name) {
		// Copy the file first, then delete the original if successful
		$copied = $this->_copy($source, $targetDir, $name);
		if (!$copied) {
			return false;
		}

		// Delete the source file
		return $this->_unlink($source);
	}

	/**
	 * Remove file
	 *
	 * @param string $path file path
	 * @return bool
	 **/
	protected function _unlink($path) {
		$objectKey = $this->getObjectKey($path);

		// Ensure we're not deleting outside our base path
		if (!$this->isInsideBase($objectKey)) {
			return false;
		}

		$bucketPath = $this->getBucketPath();

		try {
			return $this->http->S3_DeleteObject($bucketPath, $objectKey);
		} catch (Exception $e) {
			return false;
		}
	}

	/**
	 * Remove directory
	 *
	 * @param string $path directory path
	 * @return bool
	 **/
	protected function _rmdir($path) {
		$objectKey = $this->getObjectKey($path);

		// Ensure directory key has trailing slash
		if (substr($objectKey, -1) !== '/') {
			$objectKey .= '/';
		}

		// Ensure we're not deleting outside our base path
		if (!$this->isInsideBase($objectKey)) {
			return false;
		}

		$bucketPath = $this->getBucketPath();

		try {
			// First check if the directory is empty
			$xml = $this->http->s3_ListBucketObjects($bucketPath);
			if (!$this->http->get_LastMethodSuccess()) {
				return false;
			}

            // Parse XML using SimpleXML
            try {
                $xmlObj = new SimpleXMLElement($xml);
                $isEmpty = true;

                foreach ($xmlObj->Contents as $content) {
                    $key = (string)$content->Key;

                    // Skip the directory marker itself
                    if ($key === $objectKey) {
                        continue;
                    }

                    // If there's an object with this prefix, directory is not empty
                    if (strpos($key, $objectKey) === 0) {
                        $isEmpty = false;
                        break;
                    }
                }

                if (!$isEmpty) {
                    // Directory is not empty
                    return $this->setError(elFinder::ERROR_NOT_EMPTY);
                }
            } catch (Exception $e) {
                // XML parsing failed
                return false;
            }

			// Delete the directory marker object
			return $this->http->S3_DeleteObject($bucketPath, $objectKey);
		} catch (Exception $e) {
			return false;
		}
	}

	/**
	 * Get file contents
	 *
	 * @param string $path file path
	 * @return string|false
	 **/
	protected function _getContents($path) {
		$objectKey = $this->getObjectKey($path);

		// Ensure we're not accessing outside our base path
		if (!$this->isInsideBase($objectKey)) {
			return false;
		}

		$bucketPath = $this->getBucketPath();

		try {
			// Download the file as a string with UTF-8 encoding
			// Note: Use s3_DownloadString (lowercase s) for proper string return
			$content = $this->http->s3_DownloadString($bucketPath, $objectKey, 'utf-8');
            $methodSuccess = $this->http->get_LastMethodSuccess();
            if (!$methodSuccess) {
                return false;
            }

			return $content;
		} catch (Exception $e) {
			return false;
		}
	}

	/**
	 * Write a file
	 *
	 * @param string $path file path
	 * @param string $content new file content
	 * @return bool
	 **/
	protected function _filePutContents($path, $content) {
		$objectKey = $this->getObjectKey($path);

		// Ensure we're not writing outside our base path
		if (!$this->isInsideBase($objectKey)) {
			return false;
		}

		$bucketPath = $this->getBucketPath();

		try {
			// Get content type
            $ext = pathinfo($path, PATHINFO_EXTENSION);
            $contentType = $this->getMimeByExtension($ext);
            if (!$contentType) {
                $contentType = $this->getMimeByContent($content) ?: 'text/plain';
            }

			return $this->http->S3_UploadString($content, 'utf-8', $contentType, $bucketPath, $objectKey);
		} catch (Exception $e) {
			return false;
		}
	}

	/**
	 * Get MIME type from content
	 *
	 * @param string $content File content
	 * @return string MIME type or empty string
	 */
	protected function getMimeByContent($content) {
		$mime = '';

        // Try finfo if available
		if (function_exists('finfo_buffer')) {
			$finfo = finfo_open(FILEINFO_MIME_TYPE);
			$mime = finfo_buffer($finfo, $content);
			finfo_close($finfo);
		}
        // Try looking at the first few bytes for common signatures
        else {
            $first4 = substr($content, 0, 4);
            if ($first4 === "\x89PNG") {
                $mime = 'image/png';
            } elseif ($first4 === "\xff\xd8\xff\xe0" || $first4 === "\xff\xd8\xff\xe1") {
                $mime = 'image/jpeg';
            } elseif ($first4 === "GIF8") {
                $mime = 'image/gif';
            } elseif (substr($content, 0, 5) === "%PDF-") {
                $mime = 'application/pdf';
            } elseif (substr($content, 0, 2) === "PK") {
                $mime = 'application/zip';
            } elseif (strpos(substr($content, 0, 100), '<html') !== false) {
                $mime = 'text/html';
            } elseif (strpos(substr($content, 0, 100), '<?xml') !== false) {
                $mime = 'application/xml';
            }
        }

		return $mime;
	}

    /**
     * Open file and return file pointer
     *
     * @param  string  $path  file path
     * @param  string  $mode  open file mode (ignored in this driver)
     * @return resource|false
     */
    protected function _fopen($path, $mode='rb') {
        $objectKey = $this->getObjectKey($path);

		// Ensure we're not accessing outside our base path
		if (!$this->isInsideBase($objectKey)) {
			return false;
		}

        $bucketPath = $this->getBucketPath();

        // Currently only supports reading files, not writing
        if ($mode !== 'rb') {
            return false;
        }

        // Create a temporary file for the download
        $tmpPath = $this->tmpPath . DIRECTORY_SEPARATOR . md5($path . microtime(true));

        try {
            // Download the file
            $success = $this->http->S3_DownloadFile($bucketPath, $objectKey, $tmpPath);
            if (!$success) {
                return false;
            }

            // Open the temporary file
            $fp = fopen($tmpPath, $mode);
            if (!$fp) {
                unlink($tmpPath);
                return false;
            }

            // Store the file handle and temp path for later cleanup
            $handle = hash('md5', $path . microtime(true));
            $this->handles[$handle] = [
                'fp' => $fp,
                'path' => $tmpPath,
                'mode' => $mode,
                's3path' => $path,
            ];

            return $handle;
        } catch (Exception $e) {
            if (file_exists($tmpPath)) {
                unlink($tmpPath);
            }
            return false;
        }
    }

    /**
     * Close opened file
     *
     * @param  resource  $fp  file pointer
     * @param  string  $path  file path
     * @return bool
     */
    protected function _fclose($fp, $path = '') {
        if (!isset($this->handles[$fp])) {
            return false;
        }

        $handle = $this->handles[$fp];

        // Close the file pointer
        fclose($handle['fp']);

        // If the file was opened in write mode, we would upload the changes here
        // But for now we only support reading, so just delete the temp file
        if (file_exists($handle['path'])) {
            unlink($handle['path']);
        }

        // Remove from handles array
        unset($this->handles[$fp]);

        return true;
    }

    /**
     * Create a symbolic link
     * Not supported by S3
     *
     * @param string $target link target
     * @param string $path link name
     * @param string $type symlink type
     * @return bool
     **/
    protected function _symlink($target, $path, $type) {
        // Symbolic links are not supported in S3
        return false;
    }

    /**
     * Return file path from hash
     *
     * @param string $hash file hash
     * @return string|false
     */
    protected function _path($hash) {
        return $this->decode($hash);
    }

    /**
     * Convert a relative path to absolute path
     *
     * @param string $path file path
     * @return string
     */
    protected function _abspath($path) {
        // For S3, we don't have a real filesystem absolute path
        // So we just return the virtual path as is
        return $path;
    }

    /**
     * Get image dimensions
     *
     * @param string $hash file hash
     * @return array|false
     */
    protected function _dimensions($hash, $mime) {
        // We need to download the file to get dimensions
        if (($file = $this->file($hash)) == false) {
            return false;
        }

        // Make sure it's an image file
        if (!$this->canGetDimensions($mime)) {
            return false;
        }

        // Check if 'path' key exists in the file array
        if (!isset($file['path'])) {
            return false;
        }

        $path = $file['path'];
        $objectKey = $this->getObjectKey($path);

		// Ensure we're not accessing outside our base path
		if (!$this->isInsideBase($objectKey)) {
			return false;
		}

        $bucketPath = $this->getBucketPath();

        // Create a temporary file for the download
        $tmpPath = $this->tmpPath . DIRECTORY_SEPARATOR . md5($path . microtime(true));

        try {
            // Download the file
            $success = $this->http->S3_DownloadFile($bucketPath, $objectKey, $tmpPath);
            if (!$success) {
                return false;
            }

            // Get image dimensions
            $dimensions = getimagesize($tmpPath);

            unlink($tmpPath); // Clean up the temp file

            if (!$dimensions) {
                return false;
            }

            return [
                'width'  => $dimensions[0],
                'height' => $dimensions[1]
            ];
        } catch (Exception $e) {
            if (file_exists($tmpPath)) {
                unlink($tmpPath); // Clean up on error
            }
            return false;
        }
    }

    /**
     * Check if the mime type is an image that we can get dimensions for
     *
     * @param string $mime Mime type
     * @return bool
     */
    protected function canGetDimensions($mime) {
        return in_array($mime, ['image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/x-ms-bmp', 'image/webp']);
    }

    /**
     * Return true if file has a thumbnail
     *
     * @param  string  $path  file path
     * @param  array   $stat  file stat
     * @return bool
     */
    protected function _hasTmb($path, $stat) {
        // For S3, thumbnails can be generated but are not stored
        return false;
    }

    /**
     * Return true if uploads are allowed
     *
     * @param  string  $path  file path
     * @param  string  $name  file name
     * @return bool
     */
    protected function _isUploadAllowed($path, $name) {
        $targetPath = $this->_joinPath($path, $name);
        $objectKey = $this->getObjectKey($targetPath);

        // Ensure we're not uploading outside our base path
        return $this->isInsideBase($objectKey);
    }

    /**
     * Save file from uploaded file
     *
     * @param  resource|string  $fp   uploaded file content
     * @param  string           $dst  destination directory path
     * @param  string           $name file name
     * @param  string           $tmpname  temporary file path
     * @return array|false
     */
    protected function _save($fp, $dst, $name, $tmpname) {
        $path = $this->_joinPath($dst, $name);
        $objectKey = $this->getObjectKey($path);

		// Ensure we're not writing outside our base path
		if (!$this->isInsideBase($objectKey)) {
			return false;
		}

        $bucketPath = $this->getBucketPath();

        // If the upload is from a file resource or data string
        if ($tmpname === null) {
            // If $fp is a file handle, we need to read it and store it in memory or a temp file
            if (is_resource($fp)) {
                $contents = '';
                while (!feof($fp)) {
                    $contents .= fread($fp, 8192);
                }

                // Get content type
                $ext = pathinfo($name, PATHINFO_EXTENSION);
                $contentType = $this->getMimeByExtension($ext);
                if (!$contentType) {
                    $contentType = $this->getMimeByContent($contents) ?: 'application/octet-stream';
                }

                // Upload content directly
                $success = $this->http->S3_UploadString($contents, 'utf-8', $contentType, $bucketPath, $objectKey);
                if (!$success) {
                    return false;
                }
            }
            // If $fp is already a string with the contents
            else {
                // Get content type
                $ext = pathinfo($name, PATHINFO_EXTENSION);
                $contentType = $this->getMimeByExtension($ext);
                if (!$contentType) {
                    $contentType = $this->getMimeByContent($fp) ?: 'application/octet-stream';
                }

                // Upload content directly
                $success = $this->http->S3_UploadString($fp, 'utf-8', $contentType, $bucketPath, $objectKey);
                if (!$success) {
                    return false;
                }
            }
        }
        // If the upload is from a temporary file
        else {
            // Get content type
            $ext = pathinfo($name, PATHINFO_EXTENSION);
            $contentType = $this->getMimeByExtension($ext);
            if (!$contentType && function_exists('mime_content_type')) {
                $contentType = mime_content_type($tmpname) ?: 'application/octet-stream';
            } else if (!$contentType) {
                $contentType = 'application/octet-stream';
            }

            // Upload file directly from the temporary location
            $success = $this->http->S3_UploadFile($tmpname, $contentType, $bucketPath, $objectKey);
            if (!$success) {
                return false;
            }
        }

        // Return file stat on success
        return $this->stat($path);
    }

    /**
     * Resize image
     *
     * @param  string  $hash    image file
     * @param  int     $width   new width
     * @param  int     $height  new height
     * @param  int     $x       X start position for crop
     * @param  int     $y       Y start position for crop
     * @param  string  $mode    action how to resize image
     * @param  string  $bg      background color
     * @param  int     $degree  rotete degree
     * @param  int     $jpgQuality  JEPG quality (1-100)
     * @return array|false
     */
    public function resize($hash, $width, $height, $x, $y, $mode = 'resize', $bg = '', $degree = 0, $jpgQuality = null) {
        // S3 driver doesn't support image operations
        return false;
    }

    /**
     * Create archive and return its path
     *
     * @param  array   $hashes  file hashes
     * @param  string  $mime    archive mime type
     * @param  string  $name    archive name
     * @return string|bool
     */
    public function archive($hashes, $mime, $name = '') {
        // S3 driver doesn't support archive operations
        return false;
    }

    /**
     * Extract files from archive
     *
     * @param  string  $hash    file hash
     * @param  array   $makedir make directory
     * @return bool
     */
    public function extract($hash, $makedir = null) {
        // S3 driver doesn't support archive operations
        return false;
    }

    /**
     * Return content URL
     *
     * @param string $hash    file hash
     * @param array  $options options
     * @return string
     */
    public function getContentUrl($hash, $options = array()) {
        if (($file = $this->file($hash)) == false || !$file['url'] || $file['url'] == 1) {
            $path = $this->decode($hash);
            return $this->_getContentUrl($path, $options);
        }
        return $file['url'];
    }

	/**
	 * Return content URL
	 *
	 * @param string $path file path
	 * @param array $options options
	 * @return string
	 **/
	protected function _getContentUrl($path, $options) {
		$objectKey = $this->getObjectKey($path);

		// Ensure we're not accessing outside our base path
		if (!$this->isInsideBase($objectKey)) {
			return '';
		}

		try {
			// Generate a pre-signed URL that's valid for a limited time
			$expireSeconds = isset($options['expire']) ? $options['expire'] : 3600; // 1 hour default

			// Use the s3_GenerateUrlV4 method for SigV4 signed URLs
			$presignedUrl = $this->http->s3_GenerateUrlV4(true, $this->bucket, $objectKey, $expireSeconds, 's3');

			if ($presignedUrl) {
				return $presignedUrl;
			}
		} catch (Exception $e) {
			// Fall back to direct URL if pre-signed URL generation fails
		}

		// Default fallback URL (will likely require public bucket or authenticated access)
		$baseUrl = rtrim($this->endpoint, '/');
		if ($this->pathStyleUrl) {
			return $baseUrl . '/' . $this->bucket . '/' . $objectKey;
		} else {
			// Virtual hosted-style URL
			// Replace the endpoint with the bucket-specific one
			$bucketDomain = str_replace('https://s3.', 'https://' . $this->bucket . '.s3.', $baseUrl);
			return $bucketDomain . '/' . $objectKey;
		}
	}

	/**
	 * Return debug info for this driver
	 *
	 * @return array
	 **/
	public function debug() {
		$debug = parent::debug();
		$debug['bucket']        = $this->bucket;
		$debug['region']        = $this->region;
		$debug['endpoint']      = $this->endpoint;
		$debug['basePath']      = $this->basePath;
        $debug['hasLicense']    = !empty($this->chilkatLicense);
        $debug['skipBucketVerification'] = $this->skipBucketVerification;

		return $debug;
	}

    /**
     * Extract files from archive
     *
     * @param  string  $path  archive path
     * @param  array   $arc   archiver command and arguments
     * @return true
     */
    protected function _extract($path, $arc) {
        // Not supported in this driver
        return false;
    }

    /**
     * Create archive and return its path
     *
     * @param  string  $dir    target directory
     * @param  array   $files  files names list
     * @param  string  $name   archive name
     * @param  array   $arc    archiver options
     * @return string|bool
     */
    protected function _archive($dir, $files, $name, $arc) {
        // Not supported in this driver
        return false;
    }

    /**
     * Detect available archivers
     *
     * @return void
     */
    protected function _checkArchivers() {
        // No archivers available for this driver
        return;
    }

    /**
     * Change file mode (chmod)
     *
     * @param  string  $path  file path
     * @param  string  $mode  octal mode
     * @return bool
     */
    protected function _chmod($path, $mode) {
        // Not supported in S3
        return false;
    }

/**
 * Encode path to hash
 * Uses hex encoding for better CSS compatibility
 *
 * @param  string  $path  file path
 * @return string
 **/
protected function encode($path) {
    error_log("Encoding path: '$path'");

    // Normalize path
    $path = $this->_normpath($path);

    // For root path, use a special hash
    if ($path === '/' || $path === '') {
        $result = $this->id . 'root';
        error_log("Root path encoded to hash: '$result'");
        return $result;
    }

    // Use bin2hex for a CSS-safe encoding
    $hash = bin2hex($path);

    // Create the final hash with volume ID prefix
    $result = $this->id . $hash;
    error_log("Path '$path' encoded to hash: '$result'");

    return $result;
}

/**
 * Decode path from hash
 * Reverses the hex encoding
 *
 * @param  string  $hash  file hash
 * @return string
 **/
protected function decode($hash) {
    error_log("Decoding hash: '$hash'");

    if (strpos($hash, $this->id) !== 0) {
        error_log("Invalid hash prefix: $hash");
        return '';
    }

    // Extract the hash part (without the volume ID prefix)
    $h = substr($hash, strlen($this->id));

    // Special case for root
    if ($h === 'root') {
        error_log("Root hash detected, returning '/'");
        return '/';
    }

    // Convert hex back to string
    $path = hex2bin($h);
    error_log("Hash '$hash' decoded to path: '$path'");

    // Normalize path
    return $this->_normpath($path);
}

/**
 * Ensure proper parent hash for root
 * Override the stat method to force correct parent hash
 */
public function stat($path) {
    error_log("Stat called for path: '$path'");

    $stat = isset($this->cache[$path])
        ? $this->cache[$path]
        : $this->_stat($path);

    if ($stat) {
        error_log("Stat for '$path': mime=" . ($stat['mime'] ?? 'missing') .
                  ", hash=" . ($stat['hash'] ?? 'missing') .
                  ", phash=" . ($stat['phash'] ?? 'missing'));
    } else {
        error_log("No stat found for path: '$path'");
    }

    // CRITICAL FIX: Root directory must have empty phash
    if ($path === '/' || $path === '') {
        if (is_array($stat)) {
            $stat['phash'] = '';  // Force empty phash for root
            $stat['isroot'] = 1;  // Ensure root flag is set
            error_log("Forcing empty phash for root");
        }
    }

    return $stat;
}

  /**
     * Return the root directory hash
     *
     * @return string
     */
    public function root() {
    return $this->encode('/');
}

    /**
     * Override mount to ensure proper initialization
     */
    public function mount(array $opts) {
        $result = parent::mount($opts);

        // Clear cache for root to ensure we set phash correctly
        if ($result && isset($this->cache['/'])) {
            unset($this->cache['/']);
        }

        return $result;
    }

    /**
     * Get the absolute root path
     *
     * @return string
     */
    public function getVolumePath() {
        return '/';
    }



}
?>