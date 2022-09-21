@Library('libpipelines') _

hose {
    EMAIL = 'sysinternal@stratio.com'
    BUILDTOOL = 'docker'
    VERSIONING_TYPE = "stratioVersion-3-3"
    UPSTREAM_VERSION = '3.10.7'

    DEV = { config ->
            doDockers(conf: config, dockerImages: [[conf: config, dockerfile: 'Dockerfile', image: 'sysinternal-external-users-expired']])
    }
}
